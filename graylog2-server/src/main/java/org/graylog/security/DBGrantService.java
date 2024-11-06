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
package org.graylog.security;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.mongodb.BasicDBObject;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.IndexOptions;
import com.mongodb.client.model.Updates;
import org.bson.Document;
import org.graylog.grn.GRN;
import org.graylog.grn.GRNRegistry;
import org.graylog2.bindings.providers.MongoJackObjectMapperProvider;
import org.graylog2.database.MongoConnection;
import org.graylog2.database.PaginatedDbService;
import org.graylog2.plugin.database.users.User;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.inject.Singleton;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static com.google.common.base.Preconditions.checkArgument;
import static java.util.Objects.requireNonNull;
import static org.apache.commons.lang3.StringUtils.isNotBlank;

@Singleton
public class DBGrantService extends PaginatedDbService<GrantDTO> {
    public static final String COLLECTION_NAME = "grants";

    private final GRNRegistry grnRegistry;

    @Inject
    public DBGrantService(MongoConnection mongoConnection,
                          MongoJackObjectMapperProvider mapper,
                          GRNRegistry grnRegistry) {
        super(mongoConnection, mapper, GrantDTO.class, COLLECTION_NAME);
        this.grnRegistry = grnRegistry;

        if (db.listIndexes().into(new ArrayList<>()).size() < 4) {
            db.createIndex(new BasicDBObject(GrantDTO.FIELD_GRANTEE, 1), new IndexOptions().background(true));
            db.createIndex(new BasicDBObject(GrantDTO.FIELD_TARGET, 1), new IndexOptions().background(true));
            db.createIndex(
                    new BasicDBObject(GrantDTO.FIELD_GRANTEE, 1)
                            .append(GrantDTO.FIELD_CAPABILITY, 1)
                            .append(GrantDTO.FIELD_TARGET, 1),
                    new IndexOptions().unique(true).background(true));
            db.createIndex(
                    new BasicDBObject(GrantDTO.FIELD_GRANTEE, 1)
                            .append(GrantDTO.FIELD_TARGET, 1),
                    new IndexOptions().unique(true).background(true));
        }
        // TODO: Add more indices

    }

    public ImmutableSet<GrantDTO> getForGranteesOrGlobal(Set<GRN> grantees) {
        return streamQuery(Filters.or(
                Filters.in(GrantDTO.FIELD_GRANTEE, grantees),
                Filters.eq(GrantDTO.FIELD_GRANTEE, GRNRegistry.GLOBAL_USER_GRN.toString())
        )).collect(ImmutableSet.toImmutableSet());
    }

    public ImmutableSet<GrantDTO> getForGrantee(GRN grantee) {
        return streamQuery(Filters.eq(GrantDTO.FIELD_GRANTEE, grantee))
                .collect(ImmutableSet.toImmutableSet());
    }

    public ImmutableSet<GrantDTO> getForGranteeWithCapability(GRN grantee, Capability capability) {
        return streamQuery(Filters.and(
                Filters.eq(GrantDTO.FIELD_GRANTEE, grantee),
                Filters.eq(GrantDTO.FIELD_CAPABILITY, capability)
        )).collect(ImmutableSet.toImmutableSet());
    }

    public ImmutableSet<GrantDTO> getForGranteesOrGlobalWithCapability(Set<GRN> grantees, Capability capability) {
        return streamQuery(Filters.and(
                Filters.or(
                        Filters.in(GrantDTO.FIELD_GRANTEE, grantees),
                        Filters.eq(GrantDTO.FIELD_GRANTEE, GRNRegistry.GLOBAL_USER_GRN.toString())
                ),
                Filters.eq(GrantDTO.FIELD_CAPABILITY, capability)
        )).collect(ImmutableSet.toImmutableSet());
    }

    public List<GrantDTO> getForTargetAndGrantee(GRN target, GRN grantee) {
        return getForTargetAndGrantees(target, ImmutableSet.of(grantee));
    }

    public List<GrantDTO> getForTargetAndGrantees(GRN target, Set<GRN> grantees) {
        return db.find(Filters.and(
                Filters.eq(GrantDTO.FIELD_TARGET, target),
                Filters.in(GrantDTO.FIELD_GRANTEE, grantees))).into(new ArrayList<>());
    }

    public GrantDTO create(GrantDTO grantDTO, @Nullable User currentUser) {
        return create(grantDTO, requireNonNull(currentUser, "currentUser cannot be null").getName());
    }

    public GrantDTO create(GrantDTO grantDTO, String creatorUsername) {
        checkArgument(isNotBlank(creatorUsername), "creatorUsername cannot be null or empty");
        final ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);

        return save(grantDTO.toBuilder()
                .createdBy(creatorUsername)
                .createdAt(now)
                .updatedBy(creatorUsername)
                .updatedAt(now)
                .build());
    }

    public GrantDTO create(GRN grantee, Capability capability, GRN target, String creatorUsername) {
        checkArgument(grantee != null, "grantee cannot be null");
        checkArgument(capability != null, "capability cannot be null");
        checkArgument(target != null, "target cannot be null");

        return create(GrantDTO.of(grantee, capability, target), creatorUsername);
    }

    /**
     * Ensure that a grant with the requested or a higher capability exists.
     *
     * @return the created, updated or existing grant
     */
    public GrantDTO ensure(GRN grantee, Capability capability, GRN target, String creatorUsername) {
        final List<GrantDTO> existingGrants = getForTargetAndGrantee(target, grantee);
        if (existingGrants.isEmpty()) {
            return create(grantee, capability, target, creatorUsername);
        }
        // This should never happen
        Preconditions.checkState(existingGrants.size() == 1);

        final GrantDTO grantDTO = existingGrants.get(0);
        // Only upgrade capabilities: VIEW < MANAGE < OWNER
        if (capability.priority() > grantDTO.capability().priority()) {
            final GrantDTO grantUpdate = grantDTO.toBuilder().capability(capability).build();
            return save(grantUpdate);
        }
        return grantDTO;
    }

    public GrantDTO update(GrantDTO updatedGrant, @Nullable User currentUser) {
        final GrantDTO existingGrant = get(updatedGrant.id())
                .orElseThrow(() -> new IllegalArgumentException("Couldn't find grant with ID " + updatedGrant.id()));

        return save(existingGrant.toBuilder()
                .grantee(updatedGrant.grantee())
                .capability(updatedGrant.capability())
                .target(updatedGrant.target())
                .updatedBy(requireNonNull(currentUser, "currentUser cannot be null").getName())
                .updatedAt(ZonedDateTime.now(ZoneOffset.UTC))
                .build());
    }

    public ImmutableList<GrantDTO> getAll() {
        try (final Stream<GrantDTO> stream = streamAll()) {
            return stream.collect(ImmutableList.toImmutableList());
        }
    }

    public List<GrantDTO> getForTarget(GRN target) {
        return db.find(Filters.eq(GrantDTO.FIELD_TARGET, target.toString())).into(new ArrayList<>());
    }

    public int deleteForGrantee(GRN grantee) {
        return (int)db.deleteMany(Filters.eq(GrantDTO.FIELD_GRANTEE, grantee.toString())).getDeletedCount();
    }

    public int deleteForTarget(GRN target) {
        return (int)db.deleteMany(Filters.eq(GrantDTO.FIELD_TARGET, target.toString())).getDeletedCount();
    }

    public List<GrantDTO> getForTargetExcludingGrantee(GRN target, GRN grantee) {
        return db.find(Filters.and(
                Filters.eq(GrantDTO.FIELD_TARGET, target.toString()),
                Filters.ne(GrantDTO.FIELD_GRANTEE, grantee.toString())
        )).into(new ArrayList<>());
    }

    public Map<GRN, Set<GRN>> getOwnersForTargets(Collection<GRN> targets) {
        return StreamSupport.stream(db.find(Filters.and(
                Filters.in(GrantDTO.FIELD_TARGET, targets),
                Filters.eq(GrantDTO.FIELD_CAPABILITY, Capability.OWN)
        )).spliterator(), false)
                .collect(Collectors.groupingBy(
                        GrantDTO::target,
                        Collectors.mapping(GrantDTO::grantee, Collectors.toSet())
                ));
    }

    public boolean hasGrantFor(GRN grantee, Capability capability, GRN target) {
        return db.countDocuments(Filters.and(
                Filters.eq(GrantDTO.FIELD_GRANTEE, grantee),
                Filters.eq(GrantDTO.FIELD_CAPABILITY, capability),
                Filters.eq(GrantDTO.FIELD_TARGET, target)
        )) > 0;
    }
}
