package org.graylog2.periodical;

import com.google.common.primitives.Ints;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import org.graylog2.database.CollectionName;
import org.graylog2.database.MongoConnection;
import org.graylog2.plugin.Tools;
import org.graylog2.plugin.periodical.Periodical;
import org.graylog2.system.activities.SystemMessageImpl;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.TimeUnit;

public class SystemMessageCleanupPeriodical extends Periodical {

    private static final Logger LOG = LoggerFactory.getLogger(SystemMessageCleanupPeriodical.class);
    private final MongoCollection systemMessageCollection;

    public SystemMessageCleanupPeriodical(MongoConnection mongoConnection) {
        final String collectionName = SystemMessageImpl.class.getAnnotation(CollectionName.class).value();
        this.systemMessageCollection = mongoConnection.getMongoDatabase().getCollection(collectionName);
    }


    @Override
    public boolean runsForever() {
        return false;
    }

    @Override
    public boolean stopOnGracefulShutdown() {
        return false;
    }

    @Override
    public boolean masterOnly() {
        return true;
    }

    @Override
    public boolean startOnThisNode() {
        return false;
    }

    @Override
    public boolean isDaemon() {
        return false;
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
        DateTime threeMonthsAgo = Tools.nowUTC().minusMonths(3);
        long deleted = systemMessageCollection.deleteMany(Filters.lte("timestamp", threeMonthsAgo)).getDeletedCount();
        LOG.info("Deleted {} system Events", deleted);
    }
}
