package ee.eesti.authentication.configuration;

import ee.eesti.authentication.constant.LegacyPortalIntegrationConfig;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;

/**
 * this filter is set up to add session attributes depending on information from request
 */
@Component
public class CustomSessionAttributeSecurityFilter extends GenericFilterBean {

    static final String LEGACY = "LEGACY";

	static final String CALLBACK_URL = "callback_url";

	private final LegacyPortalIntegrationConfig config;

	@Value("${auth.success.redirect.whitelist:}")
	private String[] authSuccessRedirectUrlWhitelist;

	public CustomSessionAttributeSecurityFilter(LegacyPortalIntegrationConfig config) {
		this.config = config;
	}

	/**
	 * Adds callback url attribute session depending if incoming request contains such  a parameter,
	 * If incoming request doesn't contain such parameter but contains "Referer"  named header that contains legacy
	 * portal referer marker then the session will have attribute LEGACY set to true and callback url set to Referer content.
	 * Also if session has no request ip attribute set it will be set from request header
	 *
	 *
	 * @param request incoming request
	 * @param response current response
	 * @param chain filter chain to continue to
	 * @throws IOException
	 * @throws ServletException
	 *
	 */
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		HttpSession session = ((HttpServletRequest)request).getSession();
		HttpServletResponse res = (HttpServletResponse) response;
        String referer = ((HttpServletRequest) request).getHeader("Referer");

		if (request.getParameter(CALLBACK_URL) != null) {

			if(!callBackUrlAllowed(request.getParameter(CALLBACK_URL))) {
				logger.error("Callback url " + request.getParameter(CALLBACK_URL) + " is not in the allowed list");
				res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Callback url is not in allowed list");
				return;
			}

			session.setAttribute(CALLBACK_URL, request.getParameter(CALLBACK_URL));
		} else if (session.getAttribute(LEGACY) == null && referer != null && referer.contains(config.getLegacyPortalRefererMarker())) {
            session.setAttribute(LEGACY, true);
        }

		if (session.getAttribute(config.getRequestIpAttribute()) == null) {
			String ip = ((HttpServletRequest) request).getHeader(config.getRequestIpHeader());
			if (ip == null || "".equals(ip)) {
				ip = request.getRemoteAddr();
			}
			session.setAttribute(config.getRequestIpAttribute() , ip);
		}

		chain.doFilter(request, response);
	}

	private boolean callBackUrlAllowed(String url) {
		for (String wlUrl : authSuccessRedirectUrlWhitelist) {
			if (url.trim().equals(wlUrl.trim())) {
				return true;
			}
		}
		return false;
	}

}
