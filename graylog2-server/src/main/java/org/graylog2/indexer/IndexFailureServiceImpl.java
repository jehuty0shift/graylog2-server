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
package org.graylog2.indexer;

import com.mongodb.BasicDBObject;
import com.mongodb.BasicDBObjectBuilder;
import com.mongodb.DBObject;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.CreateCollectionOptions;
import org.bson.Document;
import org.bson.types.ObjectId;
import org.graylog2.database.CollectionName;
import org.graylog2.database.MongoConnection;
import org.graylog2.database.PersistedServiceImpl;
import org.joda.time.DateTime;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.util.ArrayList;
import java.util.List;

@Singleton
public class IndexFailureServiceImpl extends PersistedServiceImpl implements IndexFailureService {
    private final String collectionName;

    @Inject
    public IndexFailureServiceImpl(MongoConnection mongoConnection) {
        super(mongoConnection);

        // Make sure that the index failures collection is always created capped.
        collectionName = IndexFailureImpl.class.getAnnotation(CollectionName.class).value();
        if (!mongoConnection.getMongoDatabase().listCollectionNames().into(new ArrayList<>()).contains(collectionName)) {
            final DBObject options = BasicDBObjectBuilder.start()
                    .add("capped", true)
                    .add("size", 52428800) // 50MB max size.
                    .get();

            mongoConnection.getMongoDatabase().
                    createCollection(collectionName, new CreateCollectionOptions().capped(true).sizeInBytes(1073741824));
            MongoCollection<Document> collection = mongoConnection.getMongoDatabase().
                    getCollection(collectionName);

            collection.createIndex(new BasicDBObject("timestamp", 1));
            collection.createIndex(new BasicDBObject("letter_id", 1));
        }
    }

    @Override
    public List<IndexFailure> all(int limit, int offset) {
        final DBObject sort = new BasicDBObject("$natural", -1);
        final List<DBObject> results = query(IndexFailureImpl.class, new BasicDBObject(), sort, limit, offset);
        final List<IndexFailure> failures = new ArrayList<>(results.size());
        for (DBObject o : results) {
            failures.add(new IndexFailureImpl((ObjectId) o.get("_id"), o.toMap()));
        }

        return failures;
    }

    @Override
    public long countSince(DateTime since) {
        final BasicDBObject query = new BasicDBObject("timestamp", new BasicDBObject("$gte", since.toDate()));

        return count(IndexFailureImpl.class, query);
    }

    @Override
    public long deleteFrom(DateTime since) {
        final BasicDBObject query = new BasicDBObject("timestamp", new BasicDBObject("$lte", since.toDate()));
        return destroy(query, collectionName);
    }

    @Override
    public long totalCount() {
        return collection(IndexFailureImpl.class).countDocuments();
    }
}
