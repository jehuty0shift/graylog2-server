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
package org.graylog2.periodical;

import com.google.common.primitives.Ints;
import org.graylog2.indexer.IndexFailureService;
import org.graylog2.plugin.ServerStatus;
import org.graylog2.plugin.Tools;
import org.graylog2.plugin.lifecycles.Lifecycle;
import org.graylog2.plugin.periodical.Periodical;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.concurrent.TimeUnit;

public class IndexFailuresCleanupPeriodical extends Periodical {
    private static final Logger LOG = LoggerFactory.getLogger(IndexFailuresCleanupPeriodical.class);

    private final IndexFailureService indexFailureService;
    private final ServerStatus serverStatus;

    @Inject
    public IndexFailuresCleanupPeriodical(IndexFailureService indexFailureService,
                                          ServerStatus serverStatus) {
        this.indexFailureService = indexFailureService;
        this.serverStatus = serverStatus;
    }

    @Override
    public void doRun() {
        while (serverStatus.getLifecycle() != Lifecycle.HALTING) {
            try {
                long deletedIndexFailures = indexFailureService.deleteFrom(Tools.nowUTC().minusDays(1));
                LOG.info("deleted {} index failures", deletedIndexFailures);
            } catch (Exception e) {
                LOG.error("Could not persist index failure.", e);
            }
        }
    }

    @Override
    protected Logger getLogger() {
        return LOG;
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
        return Ints.saturatedCast(TimeUnit.DAYS.toSeconds(1L));
    }
}
