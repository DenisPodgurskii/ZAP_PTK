package org.zaproxy.addon.ptk;

import java.util.List;

/**
 * Command-line entry point to output PTK↔ZAP mappings in a format suitable for ZAP's scanners.md.
 * Each line is: <alert id> PTK - <engine> - <module name>. Sorted by alert id; missing mappings use
 * ??????.
 *
 * <p>Run with: ./gradlew runPtkScannersMd
 */
public final class PtkScannersMdOutput {

    public static void main(String[] args) {
        PtkResourcesLoader loader = new PtkResourcesLoader();
        PtkResourcesLoader.LoadedPtkResources resources = loader.loadAll();
        PtkZapMapper mapper = new PtkZapMapper(resources);

        List<String> lines = mapper.formatScannersMdLines(resources);
        for (String line : lines) {
            System.out.println(line);
        }
    }
}
