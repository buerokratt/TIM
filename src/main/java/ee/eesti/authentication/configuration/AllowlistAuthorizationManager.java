package ee.eesti.authentication.configuration;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.util.matcher.IpAddressMatcher;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * Authorizes a request when its remote address matches an entry of a comma separated allowlist.
 * <p>
 * Entries can be IP addresses, CIDR ranges or host names such as docker container names. Spring Security 7's
 * {@link IpAddressMatcher} (and so {@code hasIpAddress}) rejects host names, so they are resolved here. They are
 * resolved on each request rather than at startup because a container's IP address changes when it is recreated.
 */
@Slf4j
public class AllowlistAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private static final Pattern IPV4_OR_RANGE = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}(/\\d{1,2})?");

    private final List<IpAddressMatcher> addressMatchers = new ArrayList<>();
    private final List<String> hostNames = new ArrayList<>();

    public AllowlistAuthorizationManager(String allowlist) {
        Arrays.stream(allowlist.split(","))
                .map(String::trim)
                .filter(entry -> !entry.isEmpty())
                .forEach(entry -> {
                    if (isAddressOrRange(entry)) {
                        addressMatchers.add(new IpAddressMatcher(entry));
                    } else {
                        hostNames.add(entry);
                    }
                });
    }

    @Override
    public AuthorizationResult authorize(Supplier<? extends Authentication> authentication,
                                         RequestAuthorizationContext context) {
        return new AuthorizationDecision(isAllowed(context.getRequest().getRemoteAddr()));
    }

    boolean isAllowed(String remoteAddress) {
        return addressMatchers.stream().anyMatch(matcher -> matcher.matches(remoteAddress))
                || hostNames.stream().anyMatch(hostName -> resolvesTo(hostName, remoteAddress));
    }

    private boolean resolvesTo(String hostName, String remoteAddress) {
        try {
            return Arrays.stream(InetAddress.getAllByName(hostName))
                    .anyMatch(address -> new IpAddressMatcher(address.getHostAddress()).matches(remoteAddress));
        } catch (UnknownHostException e) {
            // A service that is not running must not break access for the other allowed callers
            log.warn("Could not resolve allowlist host name {}", hostName);
            return false;
        }
    }

    private static boolean isAddressOrRange(String entry) {
        return entry.contains(":") || IPV4_OR_RANGE.matcher(entry).matches();
    }
}
