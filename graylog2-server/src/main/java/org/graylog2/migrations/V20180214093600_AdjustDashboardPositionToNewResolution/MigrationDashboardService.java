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
package org.graylog2.migrations.V20180214093600_AdjustDashboardPositionToNewResolution;

import com.google.common.collect.Maps;
import com.mongodb.BasicDBObject;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.FindOneAndReplaceOptions;
import org.bson.Document;
import org.bson.types.ObjectId;
import org.graylog2.database.MongoConnection;
import org.graylog2.plugin.database.ValidationException;
import org.graylog2.plugin.database.validators.ValidationResult;
import org.graylog2.plugin.database.validators.Validator;
import org.graylog2.plugin.system.NodeId;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

class MigrationDashboardService {
    private static final Logger LOG = LoggerFactory.getLogger(MigrationDashboardService.class);
    private static final String COLLECTION = "dashboards";
    private final MongoConnection mongoConnection;

    @Inject
    MigrationDashboardService(MongoConnection mongoConnection) {
        this.mongoConnection = mongoConnection;
    }

    String save(MigrationDashboard model) throws ValidationException {
        Map<String, List<ValidationResult>> errors = validate(model.getValidations(), model.getFields());
        if (!errors.isEmpty()) {
            throw new ValidationException(errors);
        }

        BasicDBObject doc = new BasicDBObject(model.getFields());
        doc.put("_id", new ObjectId(model.getId())); // ID was created in constructor or taken from original doc already.

        // Do field transformations
        fieldTransformations(doc);

        /*
         * We are running an upsert. This means that the existing
         * document will be updated if the ID already exists and
         * a new document will be created if it doesn't.
         */
        BasicDBObject q = new BasicDBObject("_id", new ObjectId(model.getId()));
        collection().findOneAndReplace(q, new Document(doc), new FindOneAndReplaceOptions().upsert(true));

        return model.getId();
    }

    private Map<String, List<ValidationResult>> validate(Map<String, Validator> validators, Map<String, Object> fields) {
        if (validators == null || validators.isEmpty()) {
            return Collections.emptyMap();
        }

        final Map<String, List<ValidationResult>> validationErrors = new HashMap<>();
        for (Map.Entry<String, Validator> validation : validators.entrySet()) {
            Validator v = validation.getValue();
            String field = validation.getKey();

            try {
                ValidationResult validationResult = v.validate(fields.get(field));
                if (validationResult instanceof ValidationResult.ValidationFailed) {
                    LOG.debug("Validation failure: [{}] on field [{}]", v.getClass().getCanonicalName(), field);
                    validationErrors.computeIfAbsent(field, k -> new ArrayList<>());
                    validationErrors.get(field).add(validationResult);
                }
            } catch (Exception e) {
                final String error = "Error while trying to validate <" + field + ">, got exception: " + e;
                LOG.debug(error);
                validationErrors.computeIfAbsent(field, k -> new ArrayList<>());
                validationErrors.get(field).add(new ValidationResult.ValidationFailed(error));
            }
        }

        return validationErrors;
    }

    private void fieldTransformations(Map<String, Object> doc) {
        for (Map.Entry<String, Object> x : doc.entrySet()) {

            // Work on embedded Maps, too.
            if (x.getValue() instanceof Map) {
                x.setValue(Maps.newHashMap((Map<String, Object>) x.getValue()));
                fieldTransformations((Map<String, Object>) x.getValue());
                continue;
            }

            // JodaTime DateTime is not accepted by MongoDB. Convert to java.util.Date...
            if (x.getValue() instanceof DateTime) {
                doc.put(x.getKey(), ((DateTime) x.getValue()).toDate());
            }

            // Our own NodeID
            if (x.getValue() instanceof NodeId) {
                doc.put(x.getKey(), x.getValue().toString());
            }

        }
    }

    List<MigrationDashboard> all() {
        final List<Document> results = collection().find().into(new ArrayList<>());

        final Stream<MigrationDashboard> dashboardStream = results.stream()
                .map(o -> new MigrationDashboard(o.getObjectId(MigrationDashboard.FIELD_ID), o));
        return dashboardStream
                .collect(Collectors.toList());
    }

    long count() {
        return collection().countDocuments();
    }

    private MongoCollection<Document> collection() {
        return mongoConnection.getMongoDatabase().getCollection(COLLECTION);
    }
}
