# Strict provider selection routes KeyStore lookups through BCFIPS, which does
# not implement JKS. Record that environment mismatch, but let suites continue
# so certificate and SSL behavior not involving the JVM truststore is covered.
$fips_harness_findings ||= []

class OpenSSL::X509::Store
  alias __fips_original_set_default_paths set_default_paths

  def set_default_paths
    __fips_original_set_default_paths
  rescue OpenSSL::X509::StoreError => e
    raise unless e.message.include?('JKS')

    finding =
      'HARNESS ARTIFACT: OpenSSL::X509::Store#set_default_paths could not load ' \
      "the JVM JKS truststore through BCFIPS (#{e.message})"
    $fips_harness_findings << finding unless $fips_harness_findings.include?(finding)
    self
  end
end
