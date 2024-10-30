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
package org.graylog2;

import com.mongodb.BasicDBList;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import org.bson.Document;
import org.bson.conversions.Bson;
import org.graylog2.database.MongoConnection;
import org.graylog2.database.PersistedServiceImpl;

/**
 *  @author Lennart Koopmann <lennart@socketfeed.com>
 */
public class SystemSetting extends PersistedServiceImpl {

    private static final String COLLECTION_NAME = "system_settings";

    public SystemSetting(MongoConnection mongoConnection) {
        super(mongoConnection);
    }

    public boolean getBoolean(String key) {
        MongoCollection<Document> coll = getCollection();

        Bson query = Filters.eq("key", key);

        Document result = coll.find(query).limit(1).first();
        if (result == null) {
            return false;
        }

         return result.getBoolean("value", false);
    }

    public BasicDBList getList(String key) {
        MongoCollection<Document> coll = getCollection();
        Bson query = Filters.eq("key", key);

        Document result = coll.find(query).limit(1).first();
        if (result == null) {
            return new BasicDBList();
        }

        return new BasicDBList();
    }

    private MongoCollection<Document> getCollection() {
        return mongoConnection.getMongoDatabase().getCollection(COLLECTION_NAME);
    }

}
