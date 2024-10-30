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
package org.graylog2.grok;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.mongodb.client.FindIterable;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.IndexOptions;
import com.mongodb.client.model.Indexes;
import com.mongodb.client.result.UpdateResult;
import io.krakens.grok.api.Grok;
import io.krakens.grok.api.GrokCompiler;
import io.krakens.grok.api.exception.GrokException;
import org.bson.UuidRepresentation;
import org.bson.types.ObjectId;
import org.graylog2.bindings.providers.MongoJackObjectMapperProvider;
import org.graylog2.database.MongoConnection;
import org.graylog2.database.NotFoundException;
import org.graylog2.events.ClusterEventBus;
import org.graylog2.plugin.database.ValidationException;
import org.mongojack.JacksonMongoCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.*;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;

import static com.google.common.base.Preconditions.checkNotNull;

public class MongoDbGrokPatternService implements GrokPatternService {
    public static final String COLLECTION_NAME = "grok_patterns";
    public static final String INDEX_NAME = "idx_name_asc_unique";

    private static final Logger log = LoggerFactory.getLogger(MongoDbGrokPatternService.class);

    private final JacksonMongoCollection<GrokPattern> dbCollection;
    private final ClusterEventBus clusterBus;

    @Inject
    protected MongoDbGrokPatternService(MongoConnection mongoConnection,
                                        MongoJackObjectMapperProvider mapper,
                                        ClusterEventBus clusterBus) {

        this.dbCollection = JacksonMongoCollection.builder().withObjectMapper(mapper.get()).build(
                mongoConnection.getMongoDatabase(), COLLECTION_NAME,
                GrokPattern.class,
                UuidRepresentation.STANDARD);
        this.clusterBus = clusterBus;

        // TODO: Uncomment once there are no Graylog clusters with duplicate Grok patterns out there,
        //       probably around Graylog 4.0.0.
        // createIndex(mongoConnection);
    }

    private static void createIndex(MongoConnection mongoConnection) {
        final IndexOptions indexOptions = new IndexOptions()
                .name(INDEX_NAME)
                .unique(true);
        mongoConnection.getMongoDatabase()
                .getCollection(COLLECTION_NAME)
                .createIndex(Indexes.ascending("name"), indexOptions);
    }

    @Override
    public GrokPattern load(String patternId) throws NotFoundException {
        final GrokPattern pattern = dbCollection.findOneById(new ObjectId(patternId));
        if (pattern == null) {
            throw new NotFoundException("Couldn't find Grok pattern with ID " + patternId);
        }
        return pattern;
    }

    public Optional<GrokPattern> loadByName(String name) {
        final GrokPattern pattern = dbCollection.findOne(Filters.eq("name", name));
        return Optional.ofNullable(pattern);
    }

    @Override
    public Set<GrokPattern> bulkLoad(Collection<String> patternIds) {
        final FindIterable<GrokPattern> dbCursor = dbCollection.find(Filters.in("_id", patternIds.stream().map(ObjectId::new).collect(Collectors.toList())));
        return Collections.unmodifiableSet(dbCursor.into(new HashSet<>()));
    }

    @Override
    public Set<GrokPattern> loadAll() {
        return Collections.unmodifiableSet(dbCollection.find().into(new HashSet<>()));
    }

    @Override
    public GrokPattern save(GrokPattern pattern) throws ValidationException {
        try {
            if (!validate(pattern)) {
                throw new ValidationException("Invalid pattern " + pattern);
            }
        } catch (GrokException | PatternSyntaxException e) {
            throw new ValidationException("Invalid pattern " + pattern + "\n" + e.getMessage());
        }

        if (loadByName(pattern.name()).isPresent()) {
            throw new ValidationException("Grok pattern " + pattern.name() + " already exists");
        }

        final UpdateResult result = dbCollection.save(pattern);
        final GrokPattern savedGrokPattern = dbCollection.findOneById(result.getUpsertedId());

        clusterBus.post(GrokPatternsUpdatedEvent.create(ImmutableSet.of(savedGrokPattern.name())));

        return savedGrokPattern;
    }

    @Override
    public GrokPattern update(GrokPattern pattern) throws ValidationException {
        try {
            if (!validate(pattern)) {
                throw new ValidationException("Invalid pattern " + pattern);
            }
        } catch (GrokException | PatternSyntaxException e) {
            throw new ValidationException("Invalid pattern " + pattern + "\n" + e.getMessage());
        }

        if (pattern.id() == null) {
            throw new ValidationException("Invalid pattern " + pattern);
        }
        UpdateResult result = dbCollection.replaceOneById(new ObjectId(pattern.id()), pattern);
        if (result.getMatchedCount() > 0) {
            clusterBus.post(GrokPatternsUpdatedEvent.create(ImmutableSet.of(pattern.name())));
            return pattern;
        }
        throw new ValidationException("Invalid pattern " + pattern);
    }

    @Override
    public List<GrokPattern> saveAll(Collection<GrokPattern> patterns, boolean replace) throws ValidationException {
        if (!replace) {
            for (GrokPattern pattern : loadAll()) {
                final boolean patternExists = patterns.stream().anyMatch(p -> p.name().equals(pattern.name()));
                if (patternExists) {
                    throw new ValidationException("Grok pattern " + pattern.name() + " already exists");
                }
            }
        }

        try {
            if (!validateAll(patterns)) {
                throw new ValidationException("Invalid patterns");
            }
        } catch (GrokException | PatternSyntaxException e) {
            throw new ValidationException("Invalid patterns.\n" + e.getMessage());
        }

        if (replace) {
            deleteAll();
        }

        final ImmutableList.Builder<GrokPattern> savedPatterns = ImmutableList.builder();
        final ImmutableSet.Builder<String> patternNames = ImmutableSet.builder();
        for (final GrokPattern pattern : patterns) {
            final UpdateResult result = dbCollection.save(pattern);
            GrokPattern savedGrokPattern = pattern;
            if (result.getUpsertedId() != null) {
                savedGrokPattern = dbCollection.findOneById(result.getUpsertedId());
                savedPatterns.add(savedGrokPattern);
                patternNames.add(savedGrokPattern.name());
            } else if (result.getModifiedCount() > 0) {
                savedPatterns.add(savedGrokPattern);
                patternNames.add(savedGrokPattern.name());
            }
        }

        clusterBus.post(GrokPatternsUpdatedEvent.create(patternNames.build()));

        return savedPatterns.build();
    }

    @Override
    public Map<String, Object> match(GrokPattern pattern, String sampleData) throws GrokException {
        final Set<GrokPattern> patterns = loadAll();
        final GrokCompiler grokCompiler = GrokCompiler.newInstance();
        for (GrokPattern storedPattern : patterns) {
            grokCompiler.register(storedPattern.name(), storedPattern.pattern());
        }
        grokCompiler.register(pattern.name(), pattern.pattern());
        Grok grok = grokCompiler.compile("%{" + pattern.name() + "}");
        return grok.match(sampleData).captureFlattened();
    }

    @Override
    public boolean validate(GrokPattern pattern) throws GrokException {
        checkNotNull(pattern, "A pattern must be given");
        final Set<GrokPattern> patterns = loadAll();
        final boolean fieldsMissing = Strings.isNullOrEmpty(pattern.name()) || Strings.isNullOrEmpty(pattern.pattern());
        final GrokCompiler grokCompiler = GrokCompiler.newInstance();
        for (GrokPattern storedPattern : patterns) {
            grokCompiler.register(storedPattern.name(), storedPattern.pattern());
        }
        grokCompiler.register(pattern.name(), pattern.pattern());
        grokCompiler.compile("%{" + pattern.name() + "}");
        return !fieldsMissing;
    }

    @Override
    public boolean validateAll(Collection<GrokPattern> newPatterns) throws GrokException {
        final Set<GrokPattern> patterns = loadAll();
        final GrokCompiler grokCompiler = GrokCompiler.newInstance();

        for (GrokPattern newPattern : newPatterns) {
            final boolean fieldsMissing = Strings.isNullOrEmpty(newPattern.name()) || Strings.isNullOrEmpty(newPattern.pattern());
            if (fieldsMissing) {
                return false;
            }
            grokCompiler.register(newPattern.name(), newPattern.pattern());
        }
        for (GrokPattern storedPattern : patterns) {
            grokCompiler.register(storedPattern.name(), storedPattern.pattern());
        }
        for (GrokPattern newPattern : newPatterns) {
            grokCompiler.compile("%{" + newPattern.name() + "}");
        }
        return true;
    }

    @Override
    public int delete(String patternId) {
        final GrokPattern grokPattern;
        try {
            grokPattern = load(patternId);
        } catch (NotFoundException e) {
            log.debug("Couldn't find grok pattern with ID <{}> for deletion", patternId, e);
            return 0;
        }

        final ObjectId id = new ObjectId(patternId);
        final String name = grokPattern.name();

        final int deletedPatterns = (int) dbCollection.removeById(id).getDeletedCount();
        clusterBus.post(GrokPatternsDeletedEvent.create(ImmutableSet.of(name)));

        return deletedPatterns;
    }

    @Override
    public int deleteAll() {
        final Set<GrokPattern> grokPatterns = loadAll();
        final Set<String> patternNames = grokPatterns.stream()
                .map(GrokPattern::name)
                .collect(Collectors.toSet());

        final int deletedPatterns = (int) dbCollection.deleteMany(Filters.empty()).getDeletedCount();
        clusterBus.post(GrokPatternsDeletedEvent.create(patternNames));

        return deletedPatterns;
    }
}
