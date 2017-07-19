package com.mesosphere.sdk.offer.evaluate.security;

import com.mesosphere.sdk.api.EndpointUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

/**
 * A {@link CertificateNamesGenerator} creates relevant names for given service pod.
 */
public class CertificateNamesGenerator {

    private String serviceName;
    private String taskInstanceName;

    public CertificateNamesGenerator(String serviceName, String taskInstanceName) {
        this.serviceName = serviceName;
        this.taskInstanceName = taskInstanceName;
    }

    /**
     * Returns a Subject for service certificate.
     * @return
     */
    public X500Name getSubject() {
       return new CertificateSubjectBuilder()
                .setCommonName(EndpointUtils.toAutoIpHostname(serviceName, taskInstanceName))
                .build();
    }

    /**
     * Returns additional Subject Alternative Names for service certificates.
     * @return
     */
    public GeneralNames getSANs() {
        String autoIpWildcardName = EndpointUtils.toAutoIpHostname(serviceName, "*");
        String autoIpTaskName = EndpointUtils.toAutoIpHostname(serviceName, taskInstanceName);

        EndpointUtils.VipInfo vipInfo = new EndpointUtils.VipInfo("*", 0);
        String vipWildcardName = EndpointUtils.toVipHostname(serviceName, vipInfo);

        // TODO(mh): Include all VIP names from TaskSpec

        GeneralNames subAtlNames = new GeneralNames(
                new GeneralName[]{
                        new GeneralName(GeneralName.dNSName, autoIpTaskName),
                        new GeneralName(GeneralName.dNSName, autoIpWildcardName),
                        new GeneralName(GeneralName.dNSName, vipWildcardName),
                }
        );

        return subAtlNames;
    }

}
