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

import com.github.zafarkhaja.semver.Version;
import com.mongodb.ConnectionString;
import com.mongodb.MongoCommandException;
import com.mongodb.MongoException;
import com.mongodb.WriteConcern;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoDatabase;
import com.mongodb.internal.ExceptionUtils;
import org.bson.BsonDocument;
import org.bson.BsonInt64;
import org.bson.Document;
import org.graylog2.configuration.MongoDbConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.inject.Singleton;
import java.util.List;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Strings.isNullOrEmpty;

/**
 * MongoDB connection singleton
 */
@Singleton
public class MongoConnectionImpl implements MongoConnection {
    private static final Logger LOG = LoggerFactory.getLogger(MongoConnectionImpl.class);
    private static final Version MINIMUM_MONGODB_VERSION = Version.forIntegers(2, 4);

    private final ConnectionString mongoClientURI;

    private MongoClient m = null;
    private MongoDatabase mongoDatabase = null;

    @Inject
    public MongoConnectionImpl(final MongoDbConfiguration configuration) {
        this(configuration.getMongoClientURI());
    }

    MongoConnectionImpl(ConnectionString mongoClientURI) {
        this.mongoClientURI = checkNotNull(mongoClientURI);
    }

    /**
     * Connect the instance.
     */
    @Override
    public synchronized MongoClient connect() {
        if (m == null) {
            final String dbName = mongoClientURI.getDatabase();
            if (isNullOrEmpty(dbName)) {
                LOG.error("The MongoDB database name must not be null or empty (mongodb_uri was: {})", mongoClientURI);
                throw new RuntimeException("MongoDB database name is missing.");
            }

            m = MongoClients.create(mongoClientURI);
            mongoDatabase = m.getDatabase(dbName).withWriteConcern(WriteConcern.ACKNOWLEDGED);
        }

        try {

            final Version mongoVersion = getMongoVersion(mongoDatabase);
            if (mongoVersion != null && mongoVersion.lessThan(MINIMUM_MONGODB_VERSION)) {
                LOG.warn("You're running MongoDB {} but Graylog requires at least MongoDB {}. Please upgrade.",
                        mongoVersion, MINIMUM_MONGODB_VERSION);
            }

            return m;

        } catch (MongoCommandException e) {
            if (e.getCode() == 18) {
                throw new MongoException("Couldn't connect to MongoDB. Please check the authentication credentials.", e);
            } else {
                throw new MongoException("Couldn't connect to MongoDB: " + ExceptionUtils.MongoCommandExceptionUtils.extractErrorCodeName(ExceptionUtils.MongoCommandExceptionUtils.redacted(e).getResponse()), e);
            }
        }

    }

    @Nullable
    private Version getMongoVersion(MongoDatabase mongoDatabase) {
            final Document buildInfoResult = mongoDatabase.runCommand(new BsonDocument("buildInfo", new BsonInt64(1)));
            if (!buildInfoResult.isEmpty()) {
                final List<Integer> versionArray = buildInfoResult.getList("versionArray", Integer.class);
                if (versionArray == null || versionArray.size() < 3) {
                    LOG.debug("Couldn't retrieve MongoDB version");
                    return null;
                }

                final int majorVersion = versionArray.get(0);
                final int minorVersion = versionArray.get(1);
                final int patchVersion = versionArray.get(2);
                return Version.forIntegers(majorVersion, minorVersion, patchVersion);
            } else {
                LOG.debug("Couldn't retrieve MongoDB buildInfo: {}", buildInfoResult);
                return null;
            }
    }


    @Override
    public MongoDatabase getMongoDatabase() {
        return mongoDatabase;
    }
}
