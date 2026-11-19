package ee.eesti.authentication.service;

import ee.eesti.authentication.repository.CustomJwtTokenInfoRepository;
import ee.eesti.authentication.repository.JwtTokenInfoRepository;
import ee.eesti.authentication.repository.WhitelistRepository;
import ee.eesti.authentication.repository.entity.CustomJwtTokenInfo;
import ee.eesti.authentication.repository.entity.JwtTokenInfo;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
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
	private final WhitelistRepository whitelistRepository;


	public JwtTokenInfoService(JwtTokenInfoRepository jwtTokenInfoRepository,
							   CustomJwtTokenInfoRepository customJwtTokenInfoRepository,
							   WhitelistRepository whitelistRepository) {
		this.jwtTokenInfoRepository = jwtTokenInfoRepository;
		this.customJwtTokenInfoRepository = customJwtTokenInfoRepository;
		this.whitelistRepository = whitelistRepository;
	}

	/**
	 *
	 * @param jwtTokenUuid UUID of jwtToken
	 * @param sessionId session ID
	 * @param expiredDate expired date for token
	 * @return contains info about jwtToken
	 */
	public JwtTokenInfo createJwtTokenInfo(UUID jwtTokenUuid, String sessionId, Timestamp expiredDate) {
		return createJwtTokenInfo(jwtTokenUuid, sessionId, expiredDate, null);
	}

	/**
	 *
	 * @param jwtTokenUuid UUID of jwtToken
	 * @param sessionId session ID
	 * @param expiredDate expired date for token
	 * @param sid value of the token's "sid" claim, may be null
	 * @return contains info about jwtToken
	 */
	public JwtTokenInfo createJwtTokenInfo(UUID jwtTokenUuid, String sessionId, Timestamp expiredDate, String sid) {
		try {

			JwtTokenInfo jwtTokenInfo = new JwtTokenInfo();
			jwtTokenInfo.setExpiredDate(expiredDate);
			jwtTokenInfo.setJwtUuid(jwtTokenUuid);
			jwtTokenInfo.setSid(sid);

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


	/**
	 * Blacklists every not-yet-blacklisted JWT (both regular and custom) that carries the given "sid",
	 * and removes them from the session allowlist.
	 *
	 * @param sid value of the "sid" claim
	 * @return number of tokens blacklisted
	 */
	@Transactional
	public int blacklistBySid(String sid) {
		if (sid == null || sid.isBlank()) {
			return 0;
		}

		int count = 0;
		for (JwtTokenInfo token : jwtTokenInfoRepository.findBySidAndBlacklistedIsFalse(sid)) {
			blacklist(token);
			removeFromAllowlist(token.getJwtUuid());
			count++;
		}
		for (CustomJwtTokenInfo token : customJwtTokenInfoRepository.findBySidAndBlacklistedIsFalse(sid)) {
			blacklist(token);
			removeFromAllowlist(token.getJwtUuid());
			count++;
		}

		log.info("blacklisted {} token(s) by sid", count);
		return count;
	}

	/**
	 * Flags a custom JWT as update required ("greylisted"). It stays valid, but custom-jwt-verify answers 403 for it.
	 */
	public void markUpdateRequired(CustomJwtTokenInfo jwtTokenInfo) {
		if (!jwtTokenInfo.isUpdateRequired()) {
			jwtTokenInfo.setUpdateRequired(true);
			jwtTokenInfo.setUpdateRequiredDate(new Timestamp(System.currentTimeMillis()));
		}
		customJwtTokenInfoRepository.saveAndFlush(jwtTokenInfo);
		log.debug("customJwtTokenInfo marked update required ({})", jwtTokenInfo);
	}

	/**
	 * Flags every not-blacklisted custom JWT carrying the given "sid" as update required.
	 * The tokens stay valid; custom-jwt-verify reports them as needing an update.
	 *
	 * @param sid value of the "sid" claim
	 * @return number of tokens flagged
	 */
	@Transactional
	public int markUpdateRequiredBySid(String sid) {
		if (sid == null || sid.isBlank()) {
			return 0;
		}

		int count = 0;
		for (CustomJwtTokenInfo token : customJwtTokenInfoRepository.findBySidAndBlacklistedIsFalse(sid)) {
			markUpdateRequired(token);
			count++;
		}

		log.info("marked {} custom token(s) update required by sid", count);
		return count;
	}

	private void removeFromAllowlist(UUID jwtUuid) {
		whitelistRepository.findByJwtHash(jwtUuid.toString()).ifPresent(whitelistRepository::delete);
	}

}
