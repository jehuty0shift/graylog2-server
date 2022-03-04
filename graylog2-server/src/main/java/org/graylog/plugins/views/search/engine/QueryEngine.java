/**
 * This file is part of Graylog.
 * <p>
 * Graylog is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * <p>
 * Graylog is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p>
 * You should have received a copy of the GNU General Public License
 * along with Graylog.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.graylog.plugins.views.search.engine;

import com.google.common.collect.ImmutableSet;
import com.google.common.util.concurrent.ThreadFactoryBuilder;
import one.util.streamex.StreamEx;
import org.graylog.plugins.views.search.Query;
import org.graylog.plugins.views.search.QueryMetadata;
import org.graylog.plugins.views.search.QueryMetadataDecorator;
import org.graylog.plugins.views.search.QueryResult;
import org.graylog.plugins.views.search.Search;
import org.graylog.plugins.views.search.SearchJob;
import org.graylog.plugins.views.search.errors.QueryError;
import org.graylog.plugins.views.search.errors.SearchError;
import org.graylog.plugins.views.search.errors.SearchException;
import org.graylog.plugins.views.search.errors.SearchTypeError;
import org.graylog2.indexer.ElasticsearchException;
import org.graylog2.indexer.IndexNotFoundException;
import org.graylog2.streams.StreamService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static org.apache.commons.lang3.StringUtils.defaultIfEmpty;

@Singleton
public class QueryEngine {
    private static final Logger LOG = LoggerFactory.getLogger(QueryEngine.class);

    private final Set<QueryMetadataDecorator> queryMetadataDecorators;

    // TODO proper thread pool with tunable settings
    private final Executor queryPool;
    private final QueryBackend<? extends GeneratedQueryContext> elasticsearchBackend;
    private final StreamService streamService;

    @Inject
    public QueryEngine(QueryBackend<? extends GeneratedQueryContext> elasticsearchBackend,
                       Set<QueryMetadataDecorator> queryMetadataDecorators,
                       @Named("query_engine_thread_pool_size") int queryEngineThreadPoolSize,
                       StreamService streamService) {

        queryPool = Executors.newFixedThreadPool(queryEngineThreadPoolSize, new ThreadFactoryBuilder().setNameFormat("query-engine-%d").build());
        this.streamService = streamService;
        this.elasticsearchBackend = elasticsearchBackend;
        this.queryMetadataDecorators = queryMetadataDecorators;
    }

    private static Set<QueryResult> allOfResults(Set<CompletableFuture<QueryResult>> futures) {
        return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                .handle((aVoid, throwable) -> {
                    return futures.stream()
                            .map(f -> {
                                return f.handle((queryResult, throwable1) -> {
                                    if (throwable1 != null) {
                                        return QueryResult.incomplete();
                                    } else {
                                        return queryResult;
                                    }
                                });
                            })
                            .map(CompletableFuture::join)
                            .collect(ImmutableSet.toImmutableSet());
                })
                .join();
    }

    public QueryMetadata parse(Search search, Query query) {
        final QueryMetadata parsedMetadata = elasticsearchBackend.parse(search.parameters(), query);

        return this.queryMetadataDecorators.stream()
                .reduce((decorator1, decorator2) -> {
                    return (s, q, metadata) -> {
                        return decorator1.decorate(s, q, decorator2.decorate(s, q, metadata));
                    };
                })
                .map(decorator -> {
                    return decorator.decorate(search, query, parsedMetadata);
                })
                .orElse(parsedMetadata);
    }

    public SearchJob execute(SearchJob searchJob) {
        final QueryPlan plan = new QueryPlan(this, searchJob);

        plan.queries().forEach(query -> {
            searchJob.addQueryResultFuture(query.id(),
                    // generate and run each query, making sure we never let an exception escape
                    // if need be we default to an empty result with a failed state and the wrapped exception
                    CompletableFuture.supplyAsync(() -> {
                                return prepareAndRun(plan, searchJob, query);
                            }, queryPool)
                            .handle((queryResult, throwable) -> {
                                LOG.debug("[{}] handle query {} on streams {} ", query.id(), query.filter().toString(), query.usedStreamIds());
                                if (throwable != null) {
                                    LOG.debug("[{}] throwable isn't null", query.id());
                                    final Throwable cause = throwable.getCause();
                                    SearchError error;
                                    if (cause instanceof SearchException) {
                                        error = ((SearchException) cause).error();
                                        if (error instanceof SearchTypeError) {
                                            //This error can be caused because the attached stream to the Query doesn't exist anymore. we check that.
                                            if (error.description().contains("index_not_found_exception")) {
                                                LOG.debug("[{}] replacing index_not_found error", query.id());
                                                Set<String> nonExistingStreamIds = searchJob.getSearch().usedStreamIds().stream().filter(Predicate.not(streamService::exists)).collect(Collectors.toSet());
                                                if (!nonExistingStreamIds.isEmpty()) {
                                                    LOG.debug("[{}] the following streams don't exist {}, replacing errors ", query.id(), nonExistingStreamIds);
                                                    error = new QueryError(query, "the following streams don't exist " + nonExistingStreamIds + ", please fix your search");
                                                } else {
                                                    error = new QueryError(query, cause);
                                                }
                                            }
                                        }
                                        LOG.debug("Running query {} failed: {}", query.id(), cause);
                                        searchJob.addError(error);
                                        return QueryResult.failedQueryWithError(query, error);
                                    }
                                }
                                LOG.debug("[{}] query has following errors", query.id(), queryResult.errors().stream().map(s -> s.description()).collect(Collectors.joining()));
                                if (!queryResult.errors().isEmpty() && searchJob.getSearch().usedStreamIds().stream().anyMatch(Predicate.not(streamService::exists))) {
                                    //FIX HERE
                                    Set<String> nonExistingStreamIds = searchJob.getSearch().usedStreamIds().stream().filter(Predicate.not(streamService::exists)).collect(Collectors.toSet());
                                    LOG.debug("[{}] the following streams don't exist {}, replacing errors ", query.id(), nonExistingStreamIds);
                                    final String newDescription = "the following streams don't exist " + nonExistingStreamIds + ", please fix your search";
                                    Set<SearchError> newErrors = queryResult.errors().stream().map(r -> {
                                                if (r instanceof SearchTypeError) {
                                                    SearchTypeError Ste = (SearchTypeError) r;
                                                    if (Ste.description().contains("index_not_found_exception") && Ste.description().contains("no such index")) {
                                                        LOG.debug("[{}] replacing index_not_found error", query.id());
                                                        return new SearchTypeError(query, Ste.searchTypeId(), newDescription);
                                                    }
                                                }
                                                return r;
                                            }
                                    ).collect(Collectors.toSet());

                                    return QueryResult.builder()
                                            .query(query)
                                            .errors(newErrors)
                                            .searchTypes(queryResult.searchTypes())
                                            .executionStats(queryResult.executionStats())
                                            .state(queryResult.state())
                                            .build();
                                }
                                return queryResult;
                            })
            );
        });
        // the root is always complete
        searchJob.addQueryResultFuture("", CompletableFuture.completedFuture(QueryResult.emptyResult()));

        plan.breadthFirst().forEachOrdered(query -> {
            // if the query has an immediate result, we don't need to generate anything. this is currently only true for the dummy root query
            final CompletableFuture<QueryResult> queryResultFuture = searchJob.getQueryResultFuture(query.id());
            if (!queryResultFuture.isDone()) {
                // this is not going to throw an exception, because we will always replace it with a placeholder "FAILED" result above
                final QueryResult result = queryResultFuture.join();

            } else {
                LOG.debug("[{}] Not generating query for query {}", defaultIfEmpty(query.id(), "root"), query);
            }
        });

        LOG.debug("Search job {} executing with plan {}", searchJob.getId(), plan);
        return searchJob.seal();
    }

    private QueryResult prepareAndRun(QueryPlan plan, SearchJob searchJob, Query query) {
        final Set<Query> predecessors = plan.predecessors(query);
        LOG.debug("[{}] Processing query, requires {} results, has {} subqueries",
                defaultIfEmpty(query.id(), "root"), predecessors.size(), plan.successors(query).size());

        final QueryBackend<? extends GeneratedQueryContext> backend = getQueryBackend(query);
        LOG.debug("[{}] Using {} to generate query", query.id(), backend);

        LOG.debug("[{}] Waiting for results: {}", query.id(), predecessors);
        // gather all required results to be able to execute the current query
        final Set<QueryResult> results = allOfResults(predecessors.stream()
                .map(Query::id)
                .map(searchJob::getQueryResultFuture)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet())
        );
        LOG.debug("[{}] Preparing query execution with results of queries: ({})",
                query.id(), StreamEx.of(results.stream()).map(QueryResult::query).map(Query::id).joining());

        // with all the results done, we can execute the current query and eventually complete our own result
        // if any of this throws an exception, the handle in #execute will convert it to an error and return a "failed" result instead
        // if the backend already returns a "failed result" then nothing special happens here
        final GeneratedQueryContext generatedQueryContext = backend.generate(searchJob, query, results);
        LOG.trace("[{}] Generated query {}, running it on backend {}", query.id(), generatedQueryContext, backend);
        final QueryResult result = backend.run(searchJob, query, generatedQueryContext, results);
        LOG.debug("[{}] Query returned {}", query.id(), result);
        if (!generatedQueryContext.errors().isEmpty()) {
            Set<String> nonExistingStreamIds = searchJob.getSearch().usedStreamIds().stream().filter(Predicate.not(streamService::exists)).collect(Collectors.toSet());
            final String newDescription = "the following streams don't exist " + nonExistingStreamIds + ", please fix your search";
            Set<SearchError> newErrors = generatedQueryContext.errors().stream().map(r -> {
                        if (r instanceof SearchTypeError) {
                            SearchTypeError Ste = (SearchTypeError) r;
                            if (Ste.description().contains("index_not_found_exception") && Ste.description().contains("no such index")) {

                                LOG.debug("[{}] the following streams don't exist {}, replacing errors ", query.id(), nonExistingStreamIds);
                                return new SearchTypeError(query, Ste.searchTypeId(), newDescription);
                            }
                        }
                        return r;
                    }
            ).collect(Collectors.toSet());
            LOG.debug("[{}] Generated Query has Errors {}", query.id(), newErrors.stream().map(r -> r.description()).collect(Collectors.toList()));
            newErrors.forEach(searchJob::addError);
        }
        return result;
    }

    private QueryBackend<? extends GeneratedQueryContext> getQueryBackend(Query query) {
        return elasticsearchBackend;
    }
}
