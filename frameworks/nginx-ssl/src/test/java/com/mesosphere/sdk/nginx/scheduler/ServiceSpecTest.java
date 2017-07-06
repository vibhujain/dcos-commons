package com.mesosphere.sdk.nginx.scheduler;

import com.mesosphere.sdk.testing.BaseServiceSpecTest;
import org.junit.Test;

public class ServiceSpecTest extends BaseServiceSpecTest {

    public ServiceSpecTest() {
        super(
                "EXECUTOR_URI", "",
                "LIBMESOS_URI", "",
                "PORT_API", "8080",
                "FRAMEWORK_NAME", "nginx-ssl",
    }

    @Test
    public void testYmlBase() throws Exception {
        testYaml("svc.yml");
    }
}
