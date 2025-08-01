import com.oracle.bmc.Region;
import com.oracle.bmc.auth.BasicAuthenticationDetailsProvider;
import com.oracle.bmc.auth.SubjectTokenExchangeAuthenticationDetailProvider;
import com.oracle.bmc.objectstorage.ObjectStorageClient;
import com.oracle.bmc.objectstorage.requests.GetNamespaceRequest;
import com.oracle.bmc.objectstorage.responses.GetNamespaceResponse;

import java.util.function.Supplier;

/**
 * This example demonstrates how to use the
 * SubjectTokenExchangeAuthenticationDetailProvider
 * to authenticate calls to OCI APIs. It uses the Object Storage client to get
 * the account's
 * namespace, which implicitly validates the authentication.
 *
 * <p>
 * This example requires the following command-line arguments:
 * <ul>
 * <li>tokenExchangeUrl: The URL of the token exchange endpoint (e.g., from an
 * Identity Domain).</li>
 * <li>subjectToken: The actual subject token (e.g., a JWT from an external
 * identity provider).</li>
 * <li>audience: The audience for the token exchange (e.g., "oci").</li>
 * <li>clientCredential: The client credential for basic authentication (e.g.,
 * "client_id:client_secret").</li>
 * <li>regionId: The OCI region ID (e.g., "us-ashburn-1").</li>
 * <li>compartmentId: The OCID of the compartment to query (e.g., your tenancy
 * OCID).</li>
 * </ul>
 *
 * <p>
 * For demonstration purposes, this example uses dummy implementations for
 * SubjectTokenSupplier and SessionKeySupplier. In a real-world scenario, these
 * would
 * involve actual token retrieval and key management.
 */
public class SubjectTokenExchangeAuthenticationExample {

    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            throw new IllegalArgumentException(
                    "This example expects 4 arguments: <tokenExchangeUrl> <clientCredential> <regionId> <compartmentId>");
        }

        final String tokenExchangeUrl = args[0];
        // Pull subjectToken from environment variable
        final String subjectToken = System.getenv("OCI_SUBJECT_TOKEN");
        if (subjectToken == null || subjectToken.isEmpty()) {
            throw new IllegalArgumentException(
                    "Environment variable OCI_SUBJECT_TOKEN must be set with the subject token.");
        }
        final String clientCredential = args[1];
        final String regionId = args[2];
        final String compartmentId = args[3];

        System.out.println("--- Debug Information ---");
        System.out.println("Token Exchange URL: " + tokenExchangeUrl);
        System.out.println("Subject Token (first 10 chars): "
                + subjectToken.substring(0, Math.min(subjectToken.length(), 10)) + "...");
        System.out.println("Client Credential (first 10 chars): "
                + clientCredential.substring(0, Math.min(clientCredential.length(), 10)) + "...");
        System.out.println("Region ID: " + regionId);
        System.out.println("Compartment ID: " + compartmentId);
        System.out.println("-------------------------");

        // Configure AuthenticationDetailsProvider
        System.out.println("Configuring AuthenticationDetailsProvider...");

        // Example: Dynamic supplier fetching token from an external source
        Supplier<String> dynamicSubjectTokenSupplier = () -> {
            String token = System.getenv("OCI_SUBJECT_TOKEN");
            if (token == null || token.isEmpty()) {
                throw new IllegalStateException("Failed to fetch subject token");
            }
            return token;
        };

        // Build the SubjectTokenExchangeAuthenticationDetailProvider
        System.out.println("Building SubjectTokenExchangeAuthenticationDetailProvider...");
        BasicAuthenticationDetailsProvider provider = (BasicAuthenticationDetailsProvider) new SubjectTokenExchangeAuthenticationDetailProvider.TokenExchangeAuthenticationDetailProviderBuilder()
                .tokenExchangeUrl(tokenExchangeUrl)
                .clientCredential(clientCredential)
                .region(Region.fromRegionId(regionId))
                .subjectTokenSupplier(dynamicSubjectTokenSupplier)
                .build();
        System.out.println("SubjectTokenExchangeAuthenticationDetailProvider built successfully.");

        // Initialize Object Storage Client with the new provider
        System.out.println("Initializing Object Storage Client...");
        ObjectStorageClient osClient = ObjectStorageClient.builder()
                .region(Region.fromRegionId(regionId))
                .build(provider);

        try {
            // Make a call to Object Storage to validate authentication
            System.out.println(
                    "Attempting to get Object Storage namespace using SubjectTokenExchangeAuthenticationDetailProvider...");
            GetNamespaceResponse namespaceResponse = osClient.getNamespace(
                    GetNamespaceRequest.builder().compartmentId(compartmentId).build());

            String namespaceName = namespaceResponse.getValue();
            System.out.println("Successfully retrieved Object Storage namespace: " + namespaceName);
            System.out.println("Authentication with SubjectTokenExchangeAuthenticationDetailProvider successful!");

        } catch (Exception e) {
            System.err.println("Error during Object Storage namespace retrieval: " + e.getMessage());
            e.printStackTrace();
            throw e;
        } finally {
            osClient.close();
        }
    }
}
