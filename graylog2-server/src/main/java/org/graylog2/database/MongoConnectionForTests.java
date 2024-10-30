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
package org.graylog2.database;

import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoDatabase;

import static java.util.Objects.requireNonNull;

public class MongoConnectionForTests implements MongoConnection {
    private final MongoClient mongoClient;
    private final MongoDatabase mongoDatabase;

    public MongoConnectionForTests(MongoClient mongoClient, String dbName) {
        this.mongoClient = requireNonNull(mongoClient);
        this.mongoDatabase = mongoClient.getDatabase(dbName);
    }

    public MongoConnectionForTests(MongoClient mongoClient, MongoDatabase mongoDatabase) {
        this.mongoClient = requireNonNull(mongoClient);
        this.mongoDatabase = mongoDatabase;
    }


    @Override
    public MongoClient connect() {
        return mongoClient;
    }

    @Override
    public MongoDatabase getMongoDatabase() {
        if(mongoDatabase == null) {
            throw new IllegalStateException("MongoDatabase is unavailable.");
        }

        return mongoDatabase;
    }
}
