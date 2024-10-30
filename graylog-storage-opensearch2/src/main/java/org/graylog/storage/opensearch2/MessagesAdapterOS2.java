package org.graylog.storage.opensearch2;

import com.codahale.metrics.Meter;
import com.codahale.metrics.MetricRegistry;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Iterables;
import org.graylog2.indexer.IndexNotFoundException;
import org.graylog2.indexer.messages.*;
import org.graylog2.indexer.results.ResultMessage;
import org.graylog2.plugin.BackendVersion;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.Version;
import org.opensearch.OpenSearchException;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.core.BulkRequest;
import org.opensearch.client.opensearch.core.BulkResponse;
import org.opensearch.client.opensearch.core.GetRequest;
import org.opensearch.client.opensearch.core.GetResponse;
import org.opensearch.client.opensearch.core.bulk.BulkOperation;
import org.opensearch.client.opensearch.core.bulk.BulkResponseItem;
import org.opensearch.client.opensearch.core.bulk.IndexOperation;
import org.opensearch.client.opensearch.indices.AnalyzeRequest;
import org.opensearch.client.opensearch.indices.AnalyzeResponse;
import org.opensearch.client.opensearch.indices.analyze.AnalyzeToken;
import org.opensearch.rest.RestStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.io.IOException;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

import static com.codahale.metrics.MetricRegistry.name;

public class MessagesAdapterOS2 implements MessagesAdapter {
    private static final Logger LOG = LoggerFactory.getLogger(MessagesAdapterOS2.class);
    static final String INDEX_BLOCK_ERROR = "cluster_block_exception";
    static final String MAPPER_PARSING_EXCEPTION = "mapper_parsing_exception";
    static final String INDEX_BLOCK_REASON = "blocked by: [TOO_MANY_REQUESTS/12/index read-only / allow delete (api)";
    static final String UNAVAILABLE_SHARDS_EXCEPTION = "unavailable_shards_exception";
    static final String PRIMARY_SHARD_NOT_ACTIVE_REASON = "primary shard is not active";

    private final OpenSearchClient client;
    private final Meter invalidTimestampMeter;
    private final ChunkedBulkIndexer chunkedBulkIndexer;
    private final BackendVersion version;
    private final ObjectMapper objMapper;

    @Inject
    public MessagesAdapterOS2(OpenSearchClient openSearchClient, MetricRegistry metricRegistry, ChunkedBulkIndexer chunkedBulkIndexer, ObjectMapper objMapper) {
        this.client = openSearchClient;
        this.chunkedBulkIndexer = chunkedBulkIndexer;
        this.invalidTimestampMeter = metricRegistry.meter(name(Messages.class, "invalid-timestamps"));
        this.version = BackendVersion.fromOS(Version.from(2, 0, 0));
        this.objMapper = objMapper;
    }

    @Override
    public ResultMessage get(String messageId, String index) throws DocumentNotFoundException {
        final GetRequest getRequest = new GetRequest.Builder().index(index).id(messageId).build();

        try {
            GetResponse<Map> response = client.get(getRequest, Map.class);

            if (!response.found()) {
                throw new DocumentNotFoundException(index, messageId);
            }

            return ResultMessage.parseFromSource(messageId, index, response.source());
        } catch (IOException ex) {
            LOG.error("IO Exception when getting object", ex);
            throw new DocumentNotFoundException(index, messageId);
        }
    }

    @Override
    public List<String> analyze(String toAnalyze, String index, String analyzer) {
        try {
            final AnalyzeRequest analyzeRequest = new AnalyzeRequest.Builder().index(index).analyzer(analyzer).text(toAnalyze).build();

            AnalyzeResponse response = client.indices().analyze(analyzeRequest);

            return response.tokens().stream().map(AnalyzeToken::token).collect(Collectors.toList());

        } catch (IOException ex) {
            throw exceptionFrom(ex, ex.getMessage());
        }
    }

    private OpenSearchException exceptionFrom(Exception e, String errorMessage) {
        if (e instanceof OpenSearchException) {
            final OpenSearchException opensearchException = (OpenSearchException) e;
            if (isIndexNotFoundException(opensearchException)) {
                throw IndexNotFoundException.create(errorMessage + opensearchException.getResourceId(), opensearchException.getIndex().getName());
            }
        }
        return new OpenSearchException(errorMessage, e);
    }

    private boolean isIndexNotFoundException(OpenSearchException e) {
        return e.getMessage().contains("index_not_found_exception");
    }

    @Override
    public List<Messages.IndexingError> bulkIndex(List<IndexingRequest> messageList) throws IOException {
        return chunkedBulkIndexer.index(messageList, this::bulkIndexChunked);
    }

    private List<Messages.IndexingError> bulkIndexChunked(ChunkedBulkIndexer.Chunk command) throws ChunkedBulkIndexer.EntityTooLargeException {
        final List<IndexingRequest> messageList = command.requests;
        final int offset = command.offset;
        final int chunkSize = command.size;

        if (messageList.isEmpty()) {
            return Collections.emptyList();
        }

        final Iterable<List<IndexingRequest>> chunks = Iterables.partition(messageList.subList(offset, messageList.size()), chunkSize);
        int chunkCount = 1;
        int indexedSuccessfully = 0;
        final List<Messages.IndexingError> indexFailures = new ArrayList<>();
        for (List<IndexingRequest> chunk : chunks) {

            final BulkResponse result = runBulkRequest(indexedSuccessfully, chunk);

            indexedSuccessfully += chunk.size();

            final List<BulkResponseItem> failures = extractFailures(result);

            indexFailures.addAll(indexingErrorsFrom(failures, messageList));

            logDebugInfo(messageList, offset, chunkSize, chunkCount, result, failures);

            if (result.errors()) {
                logFailures(result, failures.size());
            }

            chunkCount++;
        }

        return indexFailures;
    }

    private List<BulkResponseItem> extractFailures(BulkResponse result) {
        return result.items().stream().filter(t -> t.status() > 399).collect(Collectors.toList());

    }

    private void logFailures(BulkResponse result, int failureCount) {
        if (LOG.isErrorEnabled() && result.errors()) {
            LOG.error("Failed to index [{}] messages. Please check the index error log in your web interface for the reason. Error: {}",
                    failureCount, result.items().stream().filter(i -> i.error() != null).findAny().map(i -> i.error() != null ? i.error().reason() : null).orElse("UNKNOWN ERROR"));
        }
    }

    private void logDebugInfo(List<IndexingRequest> messageList, int offset, int chunkSize, int chunkCount, BulkResponse result, List<BulkResponseItem> failures) {
        if (LOG.isDebugEnabled()) {
            String chunkInfo = "";
            if (chunkSize != messageList.size()) {
                chunkInfo = String.format(Locale.ROOT, " (chunk %d/%d offset %d)", chunkCount,
                        (int) Math.ceil((double) messageList.size() / chunkSize), offset);
            }
            LOG.debug("Index: Bulk indexed {} messages{}, failures: {}",
                    result.items().size(), chunkInfo, failures.size());
        }
    }

    private BulkResponse runBulkRequest(int indexedSuccessfully, List<IndexingRequest> chunk) throws ChunkedBulkIndexer.EntityTooLargeException {
        final BulkRequest bulkRequest = createBulkRequest(chunk);


        try {
            return client.bulk(bulkRequest);
        } catch (IOException e) {
            throw new org.graylog2.indexer.ElasticsearchException(e);
        } catch (OpenSearchException e) {
            for (OpenSearchException cause : e.guessRootCauses()) {
                if (cause.status().equals(RestStatus.REQUEST_ENTITY_TOO_LARGE)) {
                    throw new ChunkedBulkIndexer.EntityTooLargeException(indexedSuccessfully, indexingErrorsFrom(chunk));
                }
            }
            throw new org.graylog2.indexer.ElasticsearchException(e);
        }

    }

    private BulkRequest createBulkRequest(List<IndexingRequest> chunk) {
        final BulkRequest.Builder bulkRequest = new BulkRequest.Builder();
        List<BulkOperation> operations = new ArrayList<>(chunk.size());
        for (IndexingRequest request : chunk) {
            operations.add(indexRequestFrom(request));
        }
        return bulkRequest.operations(operations).build();
    }

    private List<Messages.IndexingError> indexingErrorsFrom(List<IndexingRequest> messageList) {
        return messageList.stream()
                .map(this::indexingErrorFrom)
                .collect(Collectors.toList());
    }

    private Messages.IndexingError indexingErrorFrom(IndexingRequest indexingRequest) {
        return Messages.IndexingError.create(indexingRequest.message(), indexingRequest.indexSet().getWriteIndexAlias());
    }

    private List<Messages.IndexingError> indexingErrorsFrom(List<BulkResponseItem> failedItems, List<IndexingRequest> messageList) {
        if (failedItems.isEmpty()) {
            return Collections.emptyList();
        }

        final Map<String, Indexable> messageMap = messageList.stream()
                .map(IndexingRequest::message)
                .distinct()
                .collect(Collectors.toMap(Indexable::getId, Function.identity()));

        return failedItems.stream()
                .map(item -> {
                    final Indexable message = messageMap.get(item.id());

                    return indexingErrorFromResponse(item, message);
                })
                .collect(Collectors.toList());
    }

    private Messages.IndexingError indexingErrorFromResponse(BulkResponseItem item, Indexable message) {
        return Messages.IndexingError.create(message, item.index(), errorTypeFromResponse(item), item.error() != null ? item.error().reason() : "Unknown Reason");
    }

    private Messages.IndexingError.ErrorType errorTypeFromResponse(BulkResponseItem item) {
        final String type = item.error() != null ? item.error().type() : "UNKNOWN";
        switch (type) {
            case MAPPER_PARSING_EXCEPTION: {
                return Messages.IndexingError.ErrorType.MappingError;
            }
            case INDEX_BLOCK_ERROR: {
                if (item.error().reason().contains(INDEX_BLOCK_REASON))
                    return Messages.IndexingError.ErrorType.IndexBlocked;
            }
            case UNAVAILABLE_SHARDS_EXCEPTION: {
                if (item.error().reason().contains(PRIMARY_SHARD_NOT_ACTIVE_REASON))
                    return Messages.IndexingError.ErrorType.IndexBlocked;
            }
            default:
                return Messages.IndexingError.ErrorType.Unknown;
        }
    }

    private BulkOperation indexRequestFrom(IndexingRequest request) {

        if (request.message() instanceof Message) {
            JsonpMessage jsonpMessage = new JsonpMessage((Message) request.message(), version);
            return new BulkOperation.Builder().index(new IndexOperation.Builder<JsonpMessage>().document(jsonpMessage).id(request.message().getId()).index(request.indexSet().getWriteIndexAlias()).build()).build();
        } else {
            Map<String, Object> jsonMessage = request.message().toElasticSearchObject(objMapper, invalidTimestampMeter, version);
            return new BulkOperation.Builder().index(new IndexOperation.Builder<Map<String, Object>>().document(jsonMessage).id(request.message().getId()).index(request.indexSet().getWriteIndexAlias()).build()).build();
        }
    }
}
