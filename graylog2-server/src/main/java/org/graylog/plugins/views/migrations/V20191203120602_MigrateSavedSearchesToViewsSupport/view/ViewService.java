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
package org.graylog.plugins.views.migrations.V20191203120602_MigrateSavedSearchesToViewsSupport.view;

import org.bson.UuidRepresentation;
import org.bson.types.ObjectId;
import org.graylog2.bindings.providers.MongoJackObjectMapperProvider;
import org.graylog2.database.MongoConnection;
import org.mongojack.JacksonMongoCollection;

import javax.inject.Inject;
import java.util.Objects;

public class ViewService {
    protected final JacksonMongoCollection<View> db;

    @Inject
    ViewService(MongoConnection mongoConnection, MongoJackObjectMapperProvider mapper) {
        this.db = JacksonMongoCollection.builder().withObjectMapper(mapper.get()).build(mongoConnection.getMongoDatabase(), "views", View.class, UuidRepresentation.STANDARD);
    }

    public ObjectId save(View view) {
        return Objects.requireNonNull(db.save(view).getUpsertedId()).asObjectId().getValue();
    }
}
