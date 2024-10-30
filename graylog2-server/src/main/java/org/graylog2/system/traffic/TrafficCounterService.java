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
package org.graylog2.system.traffic;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableMap;
import com.mongodb.BasicDBObject;
import com.mongodb.client.FindIterable;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.IndexOptions;
import com.mongodb.client.model.UpdateOptions;
import com.mongodb.client.model.Updates;
import com.mongodb.client.result.UpdateResult;
import org.bson.UuidRepresentation;
import org.bson.conversions.Bson;
import org.graylog2.bindings.providers.MongoJackObjectMapperProvider;
import org.graylog2.database.MongoConnection;
import org.graylog2.plugin.Tools;
import org.graylog2.plugin.system.NodeId;
import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.mongojack.JacksonMongoCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

public class TrafficCounterService {
    private static final Logger LOG = LoggerFactory.getLogger(TrafficCounterService.class);
    private static final String BUCKET = "bucket";

    private final JacksonMongoCollection<TrafficDto> db;

    @Inject
    public TrafficCounterService(MongoConnection mongoConnection,
                                 MongoJackObjectMapperProvider mapper) {
        db = JacksonMongoCollection.builder().withObjectMapper(mapper.get()).build(mongoConnection.getMongoDatabase(), "traffic",
                TrafficDto.class,
                UuidRepresentation.STANDARD);
        db.createIndex(new BasicDBObject(BUCKET, 1), new IndexOptions().unique(true));
    }

    private static DateTime getDayBucket(DateTime observationTime) {
        return observationTime.withMinuteOfHour(0).withSecondOfMinute(0).withMillisOfSecond(0);
    }

    public void updateTraffic(DateTime observationTime, NodeId nodeId, long inLastMinute, long outLastMinute, long decodedLastMinute) {
        // we bucket our database by days
        final DateTime dayBucket = getDayBucket(observationTime);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Updating traffic for node {} at {}:  in/decoded/out {}/{}/{} bytes",
                    nodeId.toString(), dayBucket, inLastMinute, decodedLastMinute, outLastMinute);
        }
        final UpdateResult update = db.updateOne(Filters.eq("bucket", dayBucket),
                // sigh DBUpdate.inc only takes integers, but we have a long.
                Updates.combine(
                        Updates.inc("input." + nodeId.toString(), inLastMinute),
                        Updates.inc("output." + nodeId.toString(), outLastMinute),
                        Updates.inc("decoded." + nodeId.toString(), decodedLastMinute)), new UpdateOptions().upsert(true));
        if (update.getMatchedCount() == 0 && update.getModifiedCount() == 0 && update.getUpsertedId() == null) {
            LOG.warn("Unable to update traffic of node {}: {}", nodeId, update);
        }
    }

    public TrafficHistogram clusterTrafficOfLastDays(Duration duration, Interval interval) {
        final ImmutableMap.Builder<DateTime, Long> inputBuilder = ImmutableMap.builder();
        final ImmutableMap.Builder<DateTime, Long> outputBuilder = ImmutableMap.builder();
        final ImmutableMap.Builder<DateTime, Long> decodedBuilder = ImmutableMap.builder();
        final DateTime to = getDayBucket(Tools.nowUTC());
        final DateTime from = to.minus(duration);

        final Bson query = Filters.and(
                Filters.lte(BUCKET, to),
                Filters.gt(BUCKET, from)
        );

        FindIterable<TrafficDto> cursor = db.find(query);
            cursor.forEach(trafficDto -> {
                inputBuilder.put(trafficDto.bucket(), trafficDto.input().values().stream().mapToLong(Long::valueOf).sum());
                outputBuilder.put(trafficDto.bucket(), trafficDto.output().values().stream().mapToLong(Long::valueOf).sum());
                decodedBuilder.put(trafficDto.bucket(), trafficDto.decoded().values().stream().mapToLong(Long::valueOf).sum());
            });
            Map<DateTime, Long> inputHistogram = inputBuilder.build();
            Map<DateTime, Long> outputHistogram = outputBuilder.build();
            Map<DateTime, Long> decodedHistogram = decodedBuilder.build();

            // we might need to aggregate the hourly database values to their UTC daily buckets
            if (interval == Interval.DAILY) {
                inputHistogram = aggregateToDaily(inputHistogram);
                outputHistogram = aggregateToDaily(outputHistogram);
                decodedHistogram = aggregateToDaily(decodedHistogram);
            }
            return TrafficHistogram.create(from, to, inputHistogram, outputHistogram, decodedHistogram);

    }

    public long deleteSince(DateTime since) {
        final BasicDBObject query = new BasicDBObject(BUCKET, new BasicDBObject("$lte", since.toDate()));

        return db.deleteMany(query).getDeletedCount();
    }

    private TreeMap<DateTime, Long> aggregateToDaily(Map<DateTime, Long> histogram) {
        return histogram.entrySet().stream()
                .collect(Collectors.groupingBy(entry -> entry.getKey().withTimeAtStartOfDay(),
                        TreeMap::new,
                        Collectors.mapping(Map.Entry::getValue, Collectors.summingLong(Long::valueOf))));
    }

    public enum Interval {
        HOURLY, DAILY
    }

    @AutoValue
    @JsonAutoDetect
    public abstract static class TrafficHistogram {
        @JsonCreator
        public static TrafficHistogram create(@JsonProperty("from") DateTime from,
                                              @JsonProperty("to") DateTime to,
                                              @JsonProperty("input") Map<DateTime, Long> input,
                                              @JsonProperty("output") Map<DateTime, Long> output,
                                              @JsonProperty("decoded") Map<DateTime, Long> decoded) {
            return new AutoValue_TrafficCounterService_TrafficHistogram(from, to, input, output, decoded);
        }

        @JsonProperty
        public abstract DateTime from();

        @JsonProperty
        public abstract DateTime to();

        @JsonProperty
        public abstract Map<DateTime, Long> input();

        @JsonProperty
        public abstract Map<DateTime, Long> output();

        @JsonProperty
        public abstract Map<DateTime, Long> decoded();
    }
}
