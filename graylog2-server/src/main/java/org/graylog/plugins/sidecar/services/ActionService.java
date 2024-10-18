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
package org.graylog.plugins.sidecar.services;

import com.mongodb.MongoException;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.ReplaceOptions;
import com.mongodb.client.result.DeleteResult;
import com.mongodb.client.result.UpdateResult;
import org.bson.UuidRepresentation;
import org.graylog.plugins.sidecar.rest.models.CollectorAction;
import org.graylog.plugins.sidecar.rest.models.CollectorActions;
import org.graylog2.bindings.providers.MongoJackObjectMapperProvider;
import org.graylog2.database.MongoConnection;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.mongojack.JacksonMongoCollection;

import javax.inject.Inject;
import java.util.ArrayList;
import java.util.List;

public class ActionService {
    private static final String COLLECTION_NAME = "sidecar_collector_actions";
    private final JacksonMongoCollection<CollectorActions> dbCollection;

    @Inject
    public ActionService(MongoConnection mongoConnection,
                         MongoJackObjectMapperProvider mapper){
        dbCollection = JacksonMongoCollection.builder().withObjectMapper(mapper.get()).build(mongoConnection.getMongoDatabase(), COLLECTION_NAME, CollectorActions.class, UuidRepresentation.STANDARD);
    }

    public CollectorActions fromRequest(String sidecarId, List<CollectorAction> actions) {
        CollectorActions collectorActions = findActionBySidecar(sidecarId, false);
        if (collectorActions == null) {
            return CollectorActions.create(
                    sidecarId,
                    DateTime.now(DateTimeZone.UTC),
                    actions);
        }
        List<CollectorAction> updatedActions = new ArrayList<>();
        for (final CollectorAction action : actions) {
            for (final CollectorAction existingsAction : collectorActions.action()) {
                if (!existingsAction.collectorId().equals(action.collectorId())) {
                    updatedActions.add(existingsAction);
                }
            }
            updatedActions.add(action);
        }
        return CollectorActions.create(
                collectorActions.id(),
                sidecarId,
                DateTime.now(DateTimeZone.UTC),
                updatedActions);
    }

    public CollectorActions saveAction(CollectorActions collectorActions) {
        UpdateResult updateResult=  dbCollection.replaceOne(
                Filters.eq("sidecar_id", collectorActions.sidecarId()),
                collectorActions, new ReplaceOptions().upsert(true));

        return dbCollection.findOne(Filters.eq("_id",updateResult.getUpsertedId()));
    }

    public CollectorActions findActionBySidecar(String sidecarId, boolean remove) {
        if (remove) {
            CollectorActions collectorActions = dbCollection.findOne(Filters.eq("sidecard_id",sidecarId));
            DeleteResult deleteResult=  dbCollection.deleteOne(Filters.eq("sidecar_id", sidecarId));
            if (!deleteResult.wasAcknowledged()) {
                throw new MongoException("Couldn't delete the CollectorActions");
            }
            return collectorActions;
        } else {
            return dbCollection.findOne(Filters.eq("sidecar_id", sidecarId));
        }
    }
}
