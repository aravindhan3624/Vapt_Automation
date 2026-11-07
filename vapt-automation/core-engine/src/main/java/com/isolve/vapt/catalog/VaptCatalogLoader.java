package com.isolve.vapt.catalog;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/** Loads the single shared banking-domain catalog bundled on the classpath at
 *  catalog/vapt-banking-catalog.yaml. One instance is reused by every project. */
public final class VaptCatalogLoader {

    private static volatile VaptCatalog cached;

    private VaptCatalogLoader() {}

    public static synchronized VaptCatalog load() {
        if (cached != null) return cached;
        try (InputStream in = VaptCatalogLoader.class.getClassLoader()
                .getResourceAsStream("catalog/vapt-banking-catalog.yaml")) {
            if (in == null) {
                throw new IllegalStateException("catalog/vapt-banking-catalog.yaml not found on classpath");
            }
            // catalog YAML keys are snake_case (cwe_score, tested_by, ...); Java fields are camelCase
            ObjectMapper mapper = new ObjectMapper(new YAMLFactory())
                    .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
            cached = mapper.readValue(in, VaptCatalog.class);
            return cached;
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load VAPT catalog", e);
        }
    }

    public static Optional<VaptFinding> findById(String id) {
        return load().getFindings().stream().filter(f -> f.getId().equalsIgnoreCase(id)).findFirst();
    }

    public static List<VaptFinding> automatable() {
        return load().getFindings().stream().filter(VaptFinding::isAutomatable).collect(Collectors.toList());
    }

    public static List<VaptFinding> manualOnly() {
        return load().getFindings().stream().filter(f -> !f.isAutomatable()).collect(Collectors.toList());
    }

    public static List<VaptFinding> all() {
        return Collections.unmodifiableList(load().getFindings());
    }
}
