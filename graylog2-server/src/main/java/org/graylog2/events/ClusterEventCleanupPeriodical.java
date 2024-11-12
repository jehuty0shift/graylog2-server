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
package org.graylog2.events;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.primitives.Ints;
import com.mongodb.WriteConcern;
import com.mongodb.client.model.Filters;
import com.mongodb.client.result.DeleteResult;
import org.bson.UuidRepresentation;
import org.bson.conversions.Bson;
import org.graylog2.bindings.providers.MongoJackObjectMapperProvider;
import org.graylog2.database.MongoConnection;
import org.graylog2.plugin.periodical.Periodical;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.mongojack.JacksonMongoCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.concurrent.TimeUnit;

import static com.google.common.base.Preconditions.checkNotNull;

public class ClusterEventCleanupPeriodical extends Periodical {
    private static final Logger LOG = LoggerFactory.getLogger(ClusterEventCleanupPeriodical.class);
    private static final String COLLECTION_NAME = ClusterEventPeriodical.COLLECTION_NAME;

    @VisibleForTesting
    static final long DEFAULT_MAX_EVENT_AGE = TimeUnit.DAYS.toMillis(1L);

    private final JacksonMongoCollection<ClusterEvent> dbCollection;
    private final long maxEventAge;

    @Inject
    public ClusterEventCleanupPeriodical(final MongoJackObjectMapperProvider mapperProvider,
                                         final MongoConnection mongoConnection) {
        this(JacksonMongoCollection.builder().withObjectMapper(mapperProvider.get()).build(mongoConnection.getMongoDatabase(), COLLECTION_NAME, ClusterEvent.class, UuidRepresentation.STANDARD).withWriteConcern(WriteConcern.JOURNALED),DEFAULT_MAX_EVENT_AGE);
    }

    ClusterEventCleanupPeriodical(final JacksonMongoCollection<ClusterEvent> dbCollection, final long maxEventAge) {
        this.dbCollection = checkNotNull(dbCollection);
        this.maxEventAge = maxEventAge;
    }

    @Override
    public boolean runsForever() {
        return false;
    }

    @Override
    public boolean stopOnGracefulShutdown() {
        return true;
    }

    @Override
    public boolean masterOnly() {
        return true;
    }

    @Override
    public boolean startOnThisNode() {
        return true;
    }

    @Override
    public boolean isDaemon() {
        return true;
    }

    @Override
    public int getInitialDelaySeconds() {
        return 0;
    }

    @Override
    public int getPeriodSeconds() {
        return Ints.saturatedCast(TimeUnit.HOURS.toSeconds(12L));
    }

    @Override
    protected Logger getLogger() {
        return LOG;
    }

    @Override
    public void doRun() {
        try {
            LOG.debug("Removing stale events from MongoDB collection \"{}\"", COLLECTION_NAME);

            final long timestamp = DateTime.now(DateTimeZone.UTC).getMillis() - maxEventAge;
            final Bson query = Filters.lt("timestamp", timestamp);
            final DeleteResult deleteResult = dbCollection.deleteMany(query);

            LOG.debug("Removed {} stale events from \"{}\"", deleteResult.getDeletedCount(), COLLECTION_NAME);
        } catch (Exception e) {
            LOG.warn("Error while removing stale cluster events from MongoDB", e);
        }
    }
}
