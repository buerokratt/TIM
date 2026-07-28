package ee.eesti.authentication.controller;

import ee.eesti.authentication.domain.UserInfo;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.web.servlet.ModelAndView;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class UserInfoControllerTest {

    @Test
    void userInfoViewExposesAuthenticationDetailsAsModelAttribute() {
        UserInfo userInfo = new UserInfo();
        userInfo.setFirstName("Jaan");
        userInfo.setLastName("Tamm");

        Authentication authentication = mock(Authentication.class);
        when(authentication.getDetails()).thenReturn(userInfo);

        ModelAndView modelAndView = new UserInfoController().userInfo(authentication);

        assertEquals("userinfo", modelAndView.getViewName());
        assertEquals(userInfo, modelAndView.getModel().get("userInfo"));
    }
}
