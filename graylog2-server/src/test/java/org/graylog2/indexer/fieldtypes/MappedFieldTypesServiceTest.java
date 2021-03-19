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

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import org.apache.groovy.util.Maps;
import org.graylog.plugins.views.search.rest.MappedFieldTypeDTO;
import org.graylog2.indexer.IndexSet;
import org.graylog2.indexer.IndexSetRegistry;
import org.graylog2.indexer.fieldtypes.kefla.KeflaService;
import org.graylog2.streams.StreamService;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import java.util.*;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

public class MappedFieldTypesServiceTest {
    @Rule
    public final MockitoRule mockitoRule = MockitoJUnit.rule();

    @Mock
    private StreamService streamService;

    @Mock
    private KeflaService kService;

    @Mock
    private IndexFieldTypesService indexFieldTypesService;

    private MappedFieldTypesService mappedFieldTypesService;

    @Mock
    private IndexSetRegistry indexSetRegistry;

    @Before
    public void setUp() throws Exception {
        this.mappedFieldTypesService = new MappedFieldTypesService(streamService, indexFieldTypesService, indexSetRegistry, kService, new FieldTypeMapper());
        when(streamService.indexSetIdsByIds(Collections.singleton("stream1"))).thenReturn(Collections.singleton("indexSetId"));
    }

    @Test
    public void fieldsOfSameTypeDoNotReturnCompoundTypeIfPropertiesAreDifferent() {
        final List<IndexFieldTypesDTO> fieldTypes = ImmutableList.of(
                createIndexTypes(
                        "deadbeef",
                        "testIndex",
                        FieldTypeDTO.create("field1", "keyword"),
                        FieldTypeDTO.create("field2", "long")
                ),
                createIndexTypes(
                        "affeaffe",
                        "testIndex2",
                        FieldTypeDTO.create("field1", "text"),
                        FieldTypeDTO.create("field2", "long")
                )
        );

        IndexSet iSet = Mockito.mock(IndexSet.class);

        when(indexFieldTypesService.findForIndexSets(Collections.singleton("indexSetId"))).thenReturn(fieldTypes);
        when(indexFieldTypesService.findAll()).thenReturn(fieldTypes);
        when(indexFieldTypesService.findForIndexName(any())).thenReturn(fieldTypes);
        when(iSet.getActiveWriteIndex()).thenReturn("testIndex2");
        when(iSet.getManagedIndices()).thenReturn(new String[]{"testIndex","testIndex2"});
        when(indexSetRegistry.get(any())).thenReturn(Optional.of(iSet));
        when(kService.fieldByStreamId(any(), any())).thenReturn(Maps.of("stream1", Sets.newHashSet("field1", "field2")));

        final Set<MappedFieldTypeDTO> result = this.mappedFieldTypesService.fieldTypesByStreamIds(Collections.singleton("stream1"));
        assertThat(result).containsExactlyInAnyOrder(
                MappedFieldTypeDTO.create("field2", FieldTypes.Type.createType("long", ImmutableSet.of("numeric", "enumerable"))),
                MappedFieldTypeDTO.create("field1", FieldTypes.Type.createType("string", ImmutableSet.of("compound")))
        );
    }

    @Test
    public void fieldsOfDifferentTypesDoReturnCompoundType() {
        final List<IndexFieldTypesDTO> fieldTypes = ImmutableList.of(
                createIndexTypes(
                        "deadbeef",
                        "testIndex",
                        FieldTypeDTO.create("field1", "long"),
                        FieldTypeDTO.create("field2", "long")
                ),
                createIndexTypes(
                        "affeaffe",
                        "testIndex2",
                        FieldTypeDTO.create("field1", "text"),
                        FieldTypeDTO.create("field2", "long")
                )
        );

        IndexSet iSet = Mockito.mock(IndexSet.class);

        when(indexFieldTypesService.findForIndexSets(Collections.singleton("indexSetId"))).thenReturn(fieldTypes);
        when(indexFieldTypesService.findAll()).thenReturn(fieldTypes);
        when(indexFieldTypesService.findForIndexName(any())).thenReturn(fieldTypes);
        when(iSet.getActiveWriteIndex()).thenReturn("testIndex2");
        when(iSet.getManagedIndices()).thenReturn(new String[]{"testIndex","testIndex2"});
        when(indexSetRegistry.get(any())).thenReturn(Optional.of(iSet));
        when(kService.fieldByStreamId(any(), any())).thenReturn(Maps.of("stream1", Sets.newHashSet("field1", "field2")));

        final Set<MappedFieldTypeDTO> result = this.mappedFieldTypesService.fieldTypesByStreamIds(Collections.singleton("stream1"));
        assertThat(result).containsExactlyInAnyOrder(
                MappedFieldTypeDTO.create("field2", FieldTypes.Type.createType("long", ImmutableSet.of("numeric", "enumerable"))),
                MappedFieldTypeDTO.create("field1", FieldTypes.Type.createType("compound(long,string)", ImmutableSet.of("compound")))
        );
    }

    private IndexFieldTypesDTO createIndexTypes(String indexId, String indexName, FieldTypeDTO... fieldTypes) {
        return IndexFieldTypesDTO.create(indexId, indexName, java.util.stream.Stream.of(fieldTypes).collect(Collectors.toSet()));
    }
}
