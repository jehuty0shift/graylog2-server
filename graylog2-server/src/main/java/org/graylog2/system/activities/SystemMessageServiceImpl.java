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
package org.graylog2.system.activities;

import com.google.common.collect.Lists;
import com.mongodb.BasicDBObject;
import com.mongodb.DBObject;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.IndexOptions;
import com.mongodb.client.model.Sorts;
import org.bson.Document;
import org.bson.conversions.Bson;
import org.bson.types.ObjectId;
import org.graylog2.database.MongoConnection;
import org.graylog2.database.PersistedServiceImpl;
import org.joda.time.DateTime;

import javax.inject.Inject;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

public class SystemMessageServiceImpl extends PersistedServiceImpl implements SystemMessageService {
    private static final int PER_PAGE = 30;
    private static final String TIMESTAMP_KEY = "timestamp";

    @Inject
    public SystemMessageServiceImpl(MongoConnection mongoConnection) {
        super(mongoConnection);
        final MongoCollection<BasicDBObject> collection = this.collection(SystemMessageImpl.class);
        if (!collectionTimestampIndexExists(collection)) {
            collection.createIndex(Sorts.descending(TIMESTAMP_KEY), new IndexOptions().background(true));
        }
    }

    private boolean collectionTimestampIndexExists(MongoCollection<BasicDBObject> collection) {
        List<Document> mongoIndices = StreamSupport.stream(collection.listIndexes().spliterator(), false).collect(Collectors.toList());
        if (mongoIndices.isEmpty()) {
            return false;
        }

        for (Document index: mongoIndices) {
            if (index.containsKey("name") && index.get("name").toString().contains(TIMESTAMP_KEY)) {
                return true;
            }
        }

        return false;
    }

    @Override
    public List<SystemMessage> all(int page) {
        List<SystemMessage> messages = Lists.newArrayList();

        DBObject sort = new BasicDBObject();
        sort.put(TIMESTAMP_KEY, -1);

        List<DBObject> results = query(SystemMessageImpl.class, new BasicDBObject(), sort, PER_PAGE, PER_PAGE * page);
        for (DBObject o : results) {
            messages.add(new SystemMessageImpl(new ObjectId(o.get("_id").toString()), o.toMap()));
        }

        return messages;
    }

    @Override
    public long destroySince(DateTime since) {
        final Bson query = Filters.lte(TIMESTAMP_KEY,  since.toDate());

        return (int)this.collection(SystemMessageImpl.class).deleteMany(query).getDeletedCount();
    }

    @Override
    public long totalCount() {
        return super.totalCount(SystemMessageImpl.class);
    }

    @Override
    public SystemMessage create(Map<String, Object> fields) {
        return new SystemMessageImpl(fields);
    }
}
