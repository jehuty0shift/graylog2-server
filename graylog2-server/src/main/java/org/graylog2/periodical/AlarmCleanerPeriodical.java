package org.graylog2.periodical;

import com.google.common.primitives.Ints;
import org.graylog2.alarmcallbacks.AlarmCallbackConfiguration;
import org.graylog2.alarmcallbacks.AlarmCallbackConfigurationService;
import org.graylog2.plugin.periodical.Periodical;
import org.graylog2.streams.StreamService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class AlarmCleanerPeriodical extends Periodical {

    private static final Logger LOG = LoggerFactory.getLogger(AlarmCleanerPeriodical.class);
    private final StreamService streamService;
    private final AlarmCallbackConfigurationService alarmCallbackConfigurationService;

    @Inject
    public AlarmCleanerPeriodical(StreamService streamService, AlarmCallbackConfigurationService alarmCallbackConfigurationService) {
        this.streamService = streamService;
        this.alarmCallbackConfigurationService = alarmCallbackConfigurationService;
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
        return true;
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
        return Ints.saturatedCast(TimeUnit.HOURS.toSeconds(1));
    }

    @Override
    protected Logger getLogger() {
        return null;
    }

    @Override
    public void doRun() {
        List<AlarmCallbackConfiguration> alarmList = alarmCallbackConfigurationService.loadAll();
        long count = alarmList.stream()
                .filter(alarm -> !streamService.exists(alarm.getStreamId()))
                .map(alarmCallbackConfigurationService::destroy)
                .count();
        if (count >0) {
            LOG.info("destroyed {} stray alarms", count);
        } else {
            LOG.debug("No stray alarm destroyed");
        }
    }
}
