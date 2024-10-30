/**
 * This file is part of Graylog.
 *
 * Graylog is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Graylog is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Graylog.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.graylog.plugins.pipelineprocessor.db.mongodb;

import com.google.common.collect.ImmutableSet;
import com.mongodb.MongoException;
import com.mongodb.client.FindIterable;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.IndexOptions;
import com.mongodb.client.model.Indexes;
import com.mongodb.client.model.Sorts;
import com.mongodb.client.result.DeleteResult;
import com.mongodb.client.result.InsertOneResult;
import org.bson.UuidRepresentation;
import org.bson.conversions.Bson;
import org.bson.types.ObjectId;
import org.graylog.plugins.pipelineprocessor.db.RuleDao;
import org.graylog.plugins.pipelineprocessor.db.RuleService;
import org.graylog.plugins.pipelineprocessor.events.RulesChangedEvent;
import org.graylog2.bindings.providers.MongoJackObjectMapperProvider;
import org.graylog2.database.MongoConnection;
import org.graylog2.database.NotFoundException;
import org.graylog2.events.ClusterEventBus;
import org.mongojack.JacksonMongoCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;

/**
 * A RuleService backed by a MongoDB collection.
 */
public class MongoDbRuleService implements RuleService {
    private static final Logger log = LoggerFactory.getLogger(MongoDbRuleService.class);

    private static final String COLLECTION = "pipeline_processor_rules";
    private static final String TITLE_KEY = "title";

    private final MongoCollection<RuleDao> dbCollection;
    private final ClusterEventBus clusterBus;

    @Inject
    public MongoDbRuleService(MongoConnection mongoConnection,
                              MongoJackObjectMapperProvider mapper,
                              ClusterEventBus clusterBus) {
        this.dbCollection = JacksonMongoCollection.builder().withObjectMapper(mapper.get()).build(mongoConnection.getMongoDatabase(), COLLECTION, RuleDao.class, UuidRepresentation.STANDARD);
        this.clusterBus = clusterBus;
        dbCollection.createIndex(Indexes.ascending(TITLE_KEY), new IndexOptions().unique(true));
    }

    @Override
    public RuleDao save(RuleDao rule) {
        final InsertOneResult save = dbCollection.insertOne(rule);

        final String id = Objects.requireNonNull(save.getInsertedId()).asObjectId().getValue().toHexString();
        clusterBus.post(RulesChangedEvent.updatedRuleId(id));


        return rule.toBuilder().id(id).build();
    }

    @Override
    public RuleDao load(String id) throws NotFoundException {
        final RuleDao rule = dbCollection.find(Filters.eq("_id", new ObjectId(id))).first();
        if (rule == null) {
            throw new NotFoundException("No rule with id " + id);
        }
        return rule;
    }

    @Override
    public RuleDao loadByName(String name) throws NotFoundException {
        final Bson query = Filters.eq(TITLE_KEY, name);
        final RuleDao rule = dbCollection.find(query).first();
        if (rule == null) {
            throw new NotFoundException("No rule with name " + name);
        }
        return rule;
    }

    @Override
    public Collection<RuleDao> loadAll() {
        try {
            FindIterable<RuleDao> ruleDaos = dbCollection.find().sort(Sorts.ascending(TITLE_KEY));
            return ImmutableSet.copyOf(ruleDaos);
        } catch (MongoException e) {
            log.error("Unable to load processing rules", e);
            return Collections.emptySet();
        }
    }

    @Override
    public void delete(String id) {
        final DeleteResult result = dbCollection.deleteOne(Filters.eq("_id", new ObjectId(id)));
        if (result.getDeletedCount() != 1) {
            log.error("Unable to delete rule {}", id);
        }
        clusterBus.post(RulesChangedEvent.deletedRuleId(id));
    }

    @Override
    public Collection<RuleDao> loadNamed(Collection<String> ruleNames) {
        try {
            FindIterable<RuleDao> ruleDaos = dbCollection.find(Filters.in(TITLE_KEY, ruleNames));
            return ImmutableSet.copyOf(ruleDaos);
        } catch (MongoException e) {
            log.error("Unable to bulk load rules", e);
            return Collections.emptySet();
        }
    }
}
