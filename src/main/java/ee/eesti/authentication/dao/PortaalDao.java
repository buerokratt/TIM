package ee.eesti.authentication.dao;

import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

/**
 * This class helps to perform queries related to portal db
 */
@Repository
@Transactional
public class PortaalDao {

	@PersistenceContext
	private EntityManager entityManager;

	/**
	 *
	 * @param personalCode users personal code
	 * @return rights associated to such person in the portal db
	 */
	public String getRights(String personalCode) {
		String queryString = "SELECT asutused.check_rights(?)";
		Query query = entityManager.createNativeQuery(queryString);
		query.setParameter(1, personalCode);
		return (String) query.getSingleResult();
	}


	/**
	 * Performs a login query
	 * @param sessionId session id
	 * @param personalCode users personal code
	 */
	public void executeBgLogin(String sessionId, String personalCode) {
		String queryString = "select pwa.bg_login(?, ?, ?);";
		Query query = entityManager.createNativeQuery(queryString);
		query.setParameter(1, sessionId);
		query.setParameter(2, personalCode);
		query.setParameter(3, "EST");
		query.getSingleResult();
	}
}
