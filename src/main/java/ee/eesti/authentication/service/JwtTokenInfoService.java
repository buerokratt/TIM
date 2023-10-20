package ee.eesti.authentication.service;

import ee.eesti.authentication.repository.JwtTokenInfoRepository;
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

	public JwtTokenInfoService(JwtTokenInfoRepository jwtTokenInfoRepository) {
		this.jwtTokenInfoRepository = jwtTokenInfoRepository;
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
}
