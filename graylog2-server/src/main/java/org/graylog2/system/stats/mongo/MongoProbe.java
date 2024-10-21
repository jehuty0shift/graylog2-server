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
package org.graylog2.system.stats.mongo;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.Lists;
import com.google.common.net.HostAndPort;
import com.mongodb.BasicDBObject;
import com.mongodb.MongoException;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoDatabase;
import com.mongodb.connection.ServerDescription;
import org.bson.Document;
import org.graylog2.database.MongoConnection;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.util.List;

import static com.google.common.base.Preconditions.checkNotNull;

@Singleton
public class MongoProbe {
    private static final Logger LOG = LoggerFactory.getLogger(MongoProbe.class);

    private final MongoClient mongoClient;
    private final MongoDatabase db;
    private final MongoDatabase adminDb;
    private final BuildInfo buildInfo;
    private final HostInfo hostInfo;

    @Inject
    public MongoProbe(MongoConnection mongoConnection) {
        this(mongoConnection.connect(), mongoConnection.getMongoDatabase());
    }

    @VisibleForTesting
    MongoProbe(MongoClient mongoClient, MongoDatabase db) {
        this(mongoClient, db, mongoClient.getDatabase("admin"),
                createBuildInfo(mongoClient.getDatabase("admin")), createHostInfo(mongoClient.getDatabase("admin")));
    }

    @VisibleForTesting
    MongoProbe(MongoClient mongoClient, MongoDatabase db, MongoDatabase adminDB, BuildInfo buildInfo, HostInfo hostInfo) {
        this.mongoClient = checkNotNull(mongoClient);
        this.db = checkNotNull(db);
        this.adminDb = checkNotNull(adminDB);
        this.buildInfo = buildInfo;
        this.hostInfo = hostInfo;
    }

    private static HostInfo createHostInfo(MongoDatabase adminDb) {
        try {

            final Document hostInfoResult = adminDb.runCommand(new Document("hostInfo", 1));
            final BasicDBObject systemMap = hostInfoResult.get("system", BasicDBObject.class);
            final HostInfo.System system = HostInfo.System.create(
                    new DateTime(systemMap.getDate("currentTime")),
                    systemMap.getString("hostname"),
                    systemMap.getInt("cpuAddrSize"),
                    systemMap.getLong("memSizeMB"),
                    systemMap.getInt("numCores"),
                    systemMap.getString("cpuArch"),
                    systemMap.getBoolean("numaEnabled")
            );
            final BasicDBObject osMap = hostInfoResult.get("os", BasicDBObject.class);
            final HostInfo.Os os = HostInfo.Os.create(
                    osMap.getString("type"),
                    osMap.getString("name"),
                    osMap.getString("version")
            );

            final BasicDBObject extraMap = hostInfoResult.get("extra", BasicDBObject.class);
            final HostInfo.Extra extra = HostInfo.Extra.create(
                    extraMap.getString("versionString"),
                    extraMap.getString("libcVersion"),
                    extraMap.getString("kernelVersion"),
                    extraMap.getString("cpuFrequencyMHz"),
                    extraMap.getString("cpuFeatures"),
                    extraMap.getString("scheduler"),
                    extraMap.getLong("pageSize", -1L),
                    extraMap.getLong("numPages", -1L),
                    extraMap.getLong("maxOpenFiles", -1L)
            );

            return HostInfo.create(system, os, extra);

        } catch (MongoException ex) {
            LOG.debug("Couldn't retrieve MongoDB hostInfo", ex);
        }

        return null;
    }

    private static BuildInfo createBuildInfo(MongoDatabase adminDb) {
        final BuildInfo buildInfo;
        try {
            final Document buildInfoResult = adminDb.runCommand(new Document("buildInfo", 1));
            buildInfo = BuildInfo.create(
                    buildInfoResult.getString("version"),
                    buildInfoResult.getString("gitVersion"),
                    buildInfoResult.getString("sysInfo"),
                    buildInfoResult.getString("loaderFlags"),
                    buildInfoResult.getString("compilerFlags"),
                    buildInfoResult.getString("allocator"),
                    buildInfoResult.getList("versionArray", Integer.class),
                    buildInfoResult.getString("javascriptEngine"),
                    buildInfoResult.getInteger("bits"),
                    buildInfoResult.getBoolean("debug"),
                    buildInfoResult.getLong("maxBsonObjectSize")

            );

            return buildInfo;
        } catch (MongoException ex) {
            LOG.debug("Couldn't retrieve MongoDB buildInfo", ex);
        }
        return null;
    }

    public MongoStats mongoStats() {
        try {

            final List<ServerDescription> serverAddresses = mongoClient.getClusterDescription().getServerDescriptions();
        final List<HostAndPort> servers = Lists.newArrayListWithCapacity(serverAddresses.size());
            for (ServerDescription serverAddress : serverAddresses) {
                servers.add(HostAndPort.fromParts(serverAddress.getAddress().getHost(), serverAddress.getAddress().getPort()));
        }
            final DatabaseStats dbStats;

            final Document dbStatsResult = db.runCommand(new Document("dbStats", 1));
            final BasicDBObject extentFreeListMap = dbStatsResult.get("extentFreeList", BasicDBObject.class);
            final DatabaseStats.ExtentFreeList extentFreeList;
            if (extentFreeListMap == null) {
                extentFreeList = null;
            } else {
                extentFreeList = DatabaseStats.ExtentFreeList.create(
                        extentFreeListMap.getInt("num"),
                        extentFreeListMap.getInt("totalSize")
                );
            }

            final BasicDBObject dataFileVersionMap = (BasicDBObject) dbStatsResult.get("dataFileVersion");
            final DatabaseStats.DataFileVersion dataFileVersion;
            if (dataFileVersionMap == null) {
                dataFileVersion = null;
            } else {
                dataFileVersion = DatabaseStats.DataFileVersion.create(
                        dataFileVersionMap.getInt("major"),
                        dataFileVersionMap.getInt("minor")
                );
            }

            dbStats = DatabaseStats.create(
                    dbStatsResult.getString("db"),
                    dbStatsResult.getLong("collections"),
                    dbStatsResult.getLong("objects"),
                    dbStatsResult.getDouble("avgObjSize"),
                    dbStatsResult.getLong("dataSize"),
                    dbStatsResult.getLong("storageSize"),
                    dbStatsResult.getLong("numExtents"),
                    dbStatsResult.getLong("indexes"),
                    dbStatsResult.getLong("indexSize"),
                    dbStatsResult.containsKey("fileSize") ? dbStatsResult.getLong("fileSize") : null,
                    dbStatsResult.containsKey("nsSizeMB") ? dbStatsResult.getLong("nsSizeMB") : null,
                    extentFreeList,
                    dataFileVersion
            );


        final ServerStatus serverStatus;
        final Document serverStatusResult = adminDb.runCommand(new Document("serverStatus", 1));
            final BasicDBObject connectionsMap = serverStatusResult.get("connections", BasicDBObject.class);
            final ServerStatus.Connections connections = ServerStatus.Connections.create(
                    connectionsMap.getInt("current"),
                    connectionsMap.getInt("available"),
                    connectionsMap.containsField("totalCreated") ? connectionsMap.getLong("totalCreated") : null
            );

            final BasicDBObject networkMap = (BasicDBObject) serverStatusResult.get("network");
            final ServerStatus.Network network = ServerStatus.Network.create(
                    networkMap.getInt("bytesIn"),
                    networkMap.getInt("bytesOut"),
                    networkMap.getInt("numRequests")
            );

            final BasicDBObject memoryMap = (BasicDBObject) serverStatusResult.get("mem");
            final ServerStatus.Memory memory = ServerStatus.Memory.create(
                    memoryMap.getInt("bits"),
                    memoryMap.getInt("resident"),
                    memoryMap.getInt("virtual"),
                    memoryMap.getBoolean("supported"),
                    memoryMap.getInt("mapped", -1),
                    memoryMap.getInt("mappedWithJournal", -1)
            );

            final BasicDBObject storageEngineMap = (BasicDBObject) serverStatusResult.get("storageEngine");
            final ServerStatus.StorageEngine storageEngine;
            if (storageEngineMap == null) {
                storageEngine = ServerStatus.StorageEngine.DEFAULT;
            } else {
                storageEngine = ServerStatus.StorageEngine.create(storageEngineMap.getString("name"));
            }

            final int uptime = serverStatusResult.getInteger("uptime", 0);
            serverStatus = ServerStatus.create(
                    serverStatusResult.getString("host"),
                    serverStatusResult.getString("version"),
                    serverStatusResult.getString("process"),
                    serverStatusResult.containsKey("pid")? serverStatusResult.getLong("pid"):0L,
                    uptime,
                    serverStatusResult.containsKey("uptimeMillis")? serverStatusResult.getLong("uptimeMillis") :  uptime * 1000L,
                    serverStatusResult.getInteger("uptimeEstimate"),
                    new DateTime(serverStatusResult.getDate("localTime")),
                    connections,
                    network,
                    memory,
                    storageEngine);

        // TODO Collection stats? http://docs.mongodb.org/manual/reference/command/collStats/
            return MongoStats.create(servers, buildInfo, hostInfo, serverStatus, dbStats);
        } catch (MongoException ex) {
            LOG.debug("Couldn't retrieve MongoDB dbStats", ex);
        }
        return null;
    }
}
