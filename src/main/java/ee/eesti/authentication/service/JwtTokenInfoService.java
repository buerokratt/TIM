package ee.eesti.authentication.service;

import ee.eesti.authentication.repository.CustomJwtTokenInfoRepository;
import ee.eesti.authentication.repository.JwtTokenInfoRepository;
import ee.eesti.authentication.repository.entity.CustomJwtTokenInfo;
import ee.eesti.authentication.repository.entity.JwtTokenInfo;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import rig.commons.aop.Timed;

import java.sql.Timestamp;
import java.util.UUID;

/**
 * For managing JwtTokens
 */
@Service
@Slf4j
@Timed
public class JwtTokenInfoService {

	private final JwtTokenInfoRepository jwtTokenInfoRepository;
	private final CustomJwtTokenInfoRepository customJwtTokenInfoRepository;


	public JwtTokenInfoService(JwtTokenInfoRepository jwtTokenInfoRepository,
							   CustomJwtTokenInfoRepository customJwtTokenInfoRepository) {
		this.jwtTokenInfoRepository = jwtTokenInfoRepository;
		this.customJwtTokenInfoRepository = customJwtTokenInfoRepository;
	}

	/**
	 *
	 * @param jwtTokenUuid UUID of jwtToken
	 * @param sessionId session ID
	 * @param expiredDate expired date for token
	 * @return contains info about jwtToken
	 */
	public JwtTokenInfo createJwtTokenInfo(UUID jwtTokenUuid, String sessionId, Timestamp expiredDate) {
		try {

			JwtTokenInfo jwtTokenInfo = new JwtTokenInfo();
			jwtTokenInfo.setExpiredDate(expiredDate);
			jwtTokenInfo.setJwtUuid(jwtTokenUuid);

			return jwtTokenInfoRepository.saveAndFlush(jwtTokenInfo);

		} catch (Exception e) {
			log.error("Exception on creating JwtTokenInfo", e);
			throw new IllegalStateException(e);
		}
	}


	public void blacklist(JwtTokenInfo jwtTokenInfo) {

		jwtTokenInfo.setBlacklisted(true);
		jwtTokenInfo.setBlacklistedDate(new Timestamp(System.currentTimeMillis()));

		jwtTokenInfoRepository.save(jwtTokenInfo);
		jwtTokenInfoRepository.flush();
		log.debug("jwtTokenInfo blacklisted ({})", jwtTokenInfo);
	}


	public void blacklist(CustomJwtTokenInfo jwtTokenInfo) {

		jwtTokenInfo.setBlacklisted(true);
		jwtTokenInfo.setBlacklistedDate(new Timestamp(System.currentTimeMillis()));

		customJwtTokenInfoRepository.save(jwtTokenInfo);
		customJwtTokenInfoRepository.flush();
		log.debug("customJwtTokenInfo blacklisted ({})", jwtTokenInfo);
	}

}
