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
package org.graylog2.indexer.fieldtypes;

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import org.graylog.plugins.views.search.rest.MappedFieldTypeDTO;
import org.graylog2.indexer.IndexSet;
import org.graylog2.indexer.IndexSetRegistry;
import org.graylog2.indexer.fieldtypes.kefla.KeflaService;
import org.graylog2.streams.StreamService;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.google.common.collect.ImmutableSet.of;
import static org.graylog2.indexer.fieldtypes.FieldTypes.Type.createType;

@Singleton
public class MappedFieldTypesService {
    private final StreamService streamService;
    private final IndexFieldTypesService indexFieldTypesService;
    private final KeflaService keflaService;
    private final FieldTypeMapper fieldTypeMapper;
    private final IndexSetRegistry indexSetRegistry;
    private final Map<String, IndexFieldTypesDTO> indexFieldTypesMap;

    private static final FieldTypes.Type UNKNOWN_TYPE = createType("unknown", of());
    private static final String PROP_COMPOUND_TYPE = "compound";
    private static final List<String> reservedFields = Arrays.asList("source","message","full_message");
    private static final Logger LOG = LoggerFactory.getLogger(MappedFieldTypesService.class);

    @Inject
    public MappedFieldTypesService(StreamService streamService, IndexFieldTypesService indexFieldTypesService, IndexSetRegistry indexSetRegistry, KeflaService keflaService, FieldTypeMapper fieldTypeMapper) {
        this.keflaService = keflaService;
        this.streamService = streamService;
        this.indexFieldTypesService = indexFieldTypesService;
        this.indexSetRegistry = indexSetRegistry;
        this.fieldTypeMapper = fieldTypeMapper;
        indexFieldTypesMap = this.indexFieldTypesService.findAll().stream().collect(Collectors.toMap(IndexFieldTypesDTO::indexName, Function.identity()));
        LOG.info("loaded {} indexFieldTypes.", indexFieldTypesMap.size());
    }

    public Set<MappedFieldTypeDTO> fieldTypesByStreamIds(Collection<String> streamIds) {
        DateTime dt = DateTime.now(DateTimeZone.UTC);
        DateTime globalDT = dt;
        LOG.debug("starting fieldTypesByStreamIds on {} streams at {}", streamIds.size(), dt.toString());
        final Set<String> indexSets = streamService.indexSetIdsByIds(streamIds);
        LOG.debug("streamService  indexSetIdsByIds took {} ms", DateTime.now(DateTimeZone.UTC).getMillis() - dt.getMillis());

        Map<String, IndexSet> indexSetMap = indexSets.stream().collect(Collectors.toMap(Function.identity(), id -> indexSetRegistry.get(id).get()));

        dt = DateTime.now(DateTimeZone.UTC);
        List<String> indicesToUpdate = indexSets.stream().map(id -> indexSetMap.get(id).getActiveWriteIndex()).collect(Collectors.toList());
        LOG.debug("indices to Update are {}, found in {} ms.", indicesToUpdate, DateTime.now(DateTimeZone.UTC).getMillis() - dt.getMillis());

        dt = DateTime.now(DateTimeZone.UTC);
        Set<String> fieldsByStream = keflaService.fieldByStreamId(streamIds, indicesToUpdate).values().stream().flatMap(s -> s.stream()).collect(Collectors.toSet());
        LOG.debug("Found {} fields in {} ms.", fieldsByStream.size(), DateTime.now(DateTimeZone.UTC).getMillis() - dt.getMillis());

        dt = DateTime.now(DateTimeZone.UTC);
        indexFieldTypesMap.putAll(this.indexFieldTypesService.findForIndexName(indicesToUpdate).stream().collect(Collectors.toMap(IndexFieldTypesDTO::indexName, Function.identity())));
        LOG.debug("Index types found in {} ms.", DateTime.now(DateTimeZone.UTC).getMillis() - dt.getMillis());

        dt = DateTime.now(DateTimeZone.UTC);
        //rewrite this to take indexSet ids into accounts
        final java.util.stream.Stream<MappedFieldTypeDTO> types = indexSetMap.values().stream().flatMap(iSet -> Arrays.asList(iSet.getManagedIndices()).stream())
                .flatMap(i -> indexFieldTypesMap.get(i)==null? Stream.empty():indexFieldTypesMap.get(i).fields().stream().filter(f -> fieldsByStream.contains(f.fieldName())))
                .map(this::mapPhysicalFieldType);
        LOG.debug("filtering streams took {} ms", DateTime.now(DateTimeZone.UTC).getMillis() - dt.getMillis());

        dt = DateTime.now(DateTimeZone.UTC);
        Set<MappedFieldTypeDTO> mappedFieldSet = mergeCompoundFieldTypes(types);
        LOG.debug("merge Field took {} ms", DateTime.now(DateTimeZone.UTC).getMillis() - dt.getMillis());

        LOG.debug("global field Filtering took {} ms", DateTime.now(DateTimeZone.UTC).getMillis() - globalDT.getMillis());
        return mappedFieldSet;
    }

    private MappedFieldTypeDTO mapPhysicalFieldType(FieldTypeDTO fieldType) {
        final FieldTypes.Type mappedFieldType = fieldTypeMapper.mapType(fieldType.physicalType()).orElse(UNKNOWN_TYPE);
        return MappedFieldTypeDTO.create(fieldType.fieldName(), mappedFieldType);
    }

    private Set<MappedFieldTypeDTO> mergeCompoundFieldTypes(java.util.stream.Stream<MappedFieldTypeDTO> stream) {
        return stream.collect(Collectors.groupingBy(MappedFieldTypeDTO::name, Collectors.toSet()))
                .entrySet()
                .stream()
                .map(entry -> {
                    final Set<MappedFieldTypeDTO> fieldTypes = entry.getValue();
                    final String fieldName = entry.getKey();
                    if (fieldTypes.size() == 1) {
                        return fieldTypes.iterator().next();
                    }

                    if (reservedFields.contains(fieldName)) {
                        return MappedFieldTypeDTO.create(fieldName, FieldTypeMapper.mapType("text").get());
                    }

                    final Set<String> distinctTypes = fieldTypes.stream()
                            .map(mappedFieldTypeDTO -> mappedFieldTypeDTO.type().type())
                            .sorted()
                            .collect(Collectors.toCollection(LinkedHashSet::new));
                    final String compoundFieldType = distinctTypes.size() > 1
                            ? distinctTypes.stream().collect(Collectors.joining(",", "compound(", ")"))
                            : distinctTypes.stream().findFirst().orElse("unknown");
                    final ImmutableSet<String> commonProperties = fieldTypes.stream()
                            .map(mappedFieldTypeDTO -> mappedFieldTypeDTO.type().properties())
                            .reduce((s1, s2) -> Sets.intersection(s1, s2).immutableCopy())
                            .orElse(ImmutableSet.of());
                    LOG.info("{} is compound due to types {}", fieldName, fieldTypes.stream().map(f -> "[" + f.name() + ":" + f.type() + "]").collect(Collectors.joining(",")));
                    final ImmutableSet<String> properties = ImmutableSet.<String>builder().addAll(commonProperties).add(PROP_COMPOUND_TYPE).build();
                    return MappedFieldTypeDTO.create(fieldName, createType(compoundFieldType, properties));

                })
                .collect(Collectors.toSet());

    }
}
