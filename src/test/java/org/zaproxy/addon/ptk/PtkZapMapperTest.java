package org.zaproxy.addon.ptk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link PtkZapMapper}: alert reference lookup, uniqueness check, and scanners.md
 * format. Includes a test that the mapping file contains all mappings for the module definitions.
 */
class PtkZapMapperTest {

    private PtkResourcesLoader.LoadedPtkResources resources;
    private PtkZapMapper mapper;

    @BeforeEach
    void setUp() {
        PtkResourcesLoader loader = new PtkResourcesLoader();
        resources = loader.loadAll();
        if (resources.getZapMapping() != null) {
            mapper = new PtkZapMapper(resources);
        }
    }

    @Test
    void mappingFileHasAllMappings() {
        assertNotNull(resources.getZapMapping(), "zap-mapping.json must be loadable");
        assertNotNull(mapper, "mapper must be created from resources");
        PtkZapMapper.OneToOneCheckResult result = mapper.checkUniqueAlertReferences(resources);
        assertTrue(
                result.isOneToOne(),
                "Every module and rule in the module definition files must have a unique alert"
                        + " reference in zap-mapping.json. Errors: "
                        + result.getErrors());
        assertTrue(
                result.getErrors().isEmpty(),
                "Expected no missing or duplicate mappings: " + result.getErrors());
    }

    @Test
    void getZapAlertReference_returnsExpectedRef() {
        assumeMappingLoaded();
        String ref = mapper.getZapAlertReference("dom-xss", "no-inner-outer-html");
        assertNotNull(ref);
        assertTrue(ref.startsWith("220000_"), "SAST dom-xss base is 220000");
    }

    @Test
    void getZapAlertReference_unknownModule_returnsNull() {
        assumeMappingLoaded();
        assertNull(mapper.getZapAlertReference("no-such-module", "any-rule"));
    }

    @Test
    void getZapAlertReference_unknownRule_returnsNull() {
        assumeMappingLoaded();
        assertNull(mapper.getZapAlertReference("dom-xss", "no-such-rule"));
    }

    @Test
    void getModuleIdAndRuleId_returnsExpectedModuleAndRule() {
        assumeMappingLoaded();
        PtkZapMapper.ModuleAndRule mar = mapper.getModuleIdAndRuleId("220000_1");
        assertNotNull(mar);
        assertEquals("dom-xss", mar.getModuleId());
        assertNotNull(mar.getRuleId());
    }

    @Test
    void getModuleIdAndRuleId_unknownRef_returnsNull() {
        assumeMappingLoaded();
        assertNull(mapper.getModuleIdAndRuleId("999999_1"));
    }

    @Test
    void checkUniqueAlertReferences_whenAllMapped_returnsOneToOne() {
        assumeMappingLoaded();
        PtkZapMapper.OneToOneCheckResult result = mapper.checkUniqueAlertReferences(resources);
        assertTrue(result.isOneToOne());
    }

    @Test
    void formatScannersMdLines_returnsOneLinePerModule() {
        assumeMappingLoaded();
        List<String> lines = mapper.formatScannersMdLines(resources);
        assertNotNull(lines);
        assertTrue(lines.size() >= 20, "Expected at least 20 module lines (DAST+IAST+SAST)");
        String first = lines.get(0);
        assertTrue(
                first.contains("PTK -"),
                "Each line should be in format '<id>  PTK - <engine> - <name>': " + first);
    }

    @Test
    void formatScannersMdLines_eachLineHasExpectedFormat() {
        assumeMappingLoaded();
        List<String> lines = mapper.formatScannersMdLines(resources);
        for (String line : lines) {
            assertTrue(
                    line.matches("\\d+\\s{2}PTK - (DAST|IAST|SAST) - .+"),
                    "Line should match '<baseId>  PTK - <engine> - <name>': " + line);
        }
    }

    private void assumeMappingLoaded() {
        Assumptions.assumeTrue(
                mapper != null, "zap-mapping.json or module resources not available");
    }
}
