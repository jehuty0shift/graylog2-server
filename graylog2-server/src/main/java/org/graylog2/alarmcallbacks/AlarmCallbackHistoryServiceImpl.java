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
package org.graylog2.alarmcallbacks;

import com.mongodb.client.model.Filters;
import com.mongodb.client.model.Indexes;
import com.mongodb.client.result.UpdateResult;
import org.bson.UuidRepresentation;
import org.bson.types.ObjectId;
import org.graylog2.alerts.Alert;
import org.graylog2.bindings.providers.MongoJackObjectMapperProvider;
import org.graylog2.database.CollectionName;
import org.graylog2.database.MongoConnection;
import org.graylog2.plugin.alarms.AlertCondition;
import org.graylog2.rest.models.alarmcallbacks.AlarmCallbackError;
import org.graylog2.rest.models.alarmcallbacks.AlarmCallbackSuccess;
import org.mongojack.JacksonMongoCollection;

import javax.inject.Inject;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public class AlarmCallbackHistoryServiceImpl implements AlarmCallbackHistoryService {
    private final JacksonMongoCollection<AlarmCallbackHistoryImpl> coll;

    @Inject
    public AlarmCallbackHistoryServiceImpl(MongoConnection mongoConnection,
                                           MongoJackObjectMapperProvider mapperProvider) {
        final String collectionName = AlarmCallbackHistoryImpl.class.getAnnotation(CollectionName.class).value();
        this.coll = JacksonMongoCollection.builder().withObjectMapper(mapperProvider.get()).build(mongoConnection.getMongoDatabase(), collectionName, AlarmCallbackHistoryImpl.class, UuidRepresentation.STANDARD);
        coll.createIndex(Indexes.ascending(AlarmCallbackHistoryImpl.FIELD_ALERTID));
    }

    @Override
    public List<AlarmCallbackHistory> getForAlertId(String alertId) {
        return Collections.unmodifiableList(coll.find(Filters.eq(AlarmCallbackHistoryImpl.FIELD_ALERTID, alertId)).into(new ArrayList<>()));
    }

    @Override
    public AlarmCallbackHistory success(AlarmCallbackConfiguration alarmCallbackConfiguration, Alert alert, AlertCondition alertCondition) {
        return AlarmCallbackHistoryImpl.create(new ObjectId().toHexString(), alarmCallbackConfiguration, alert, alertCondition, AlarmCallbackSuccess.create());
    }

    @Override
    public AlarmCallbackHistory error(AlarmCallbackConfiguration alarmCallbackConfiguration, Alert alert, AlertCondition alertCondition, String error) {
        return AlarmCallbackHistoryImpl.create(new ObjectId().toHexString(), alarmCallbackConfiguration, alert, alertCondition, AlarmCallbackError.create(error));
    }

    @Override
    public AlarmCallbackHistory save(AlarmCallbackHistory alarmCallbackHistory) {
        final AlarmCallbackHistoryImpl historyImpl = implOrFail(alarmCallbackHistory);
        final UpdateResult writeResult = coll.save(historyImpl);
        return AlarmCallbackHistoryImpl.create(Objects.requireNonNull(writeResult.getUpsertedId()).asObjectId().getValue().toHexString(),
                alarmCallbackHistory.alarmcallbackConfiguration(),
                alarmCallbackHistory.alertId(),
                alarmCallbackHistory.alertConditionId(),
                alarmCallbackHistory.result(),
                alarmCallbackHistory.createdAt());
    }


    private AlarmCallbackHistoryImpl implOrFail(AlarmCallbackHistory history) {
        final AlarmCallbackHistoryImpl historyImpl;
        if (history instanceof AlarmCallbackHistoryImpl) {
            historyImpl = (AlarmCallbackHistoryImpl) history;
            return historyImpl;
        } else {
            throw new IllegalArgumentException("Supplied output must be of implementation type AlarmCallbackHistoryImpl, not " + history.getClass());
        }
    }
}
