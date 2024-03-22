package io.security.corespringsecurity.controller.user;

import io.security.corespringsecurity.domain.dto.AccountDto;
import io.security.corespringsecurity.domain.entity.Account;
import io.security.corespringsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import java.security.Principal;

@Controller
@RequiredArgsConstructor
public class UserController {

	private final PasswordEncoder passwordEncoder;
	private final UserService userService;

	@GetMapping("/users")
	public String createUser() {
		return "/user/login/register";
	}

	@PostMapping("/users")
	public String createUser(AccountDto accountDto) {
		ModelMapper modelMapper = new ModelMapper();
		Account account = modelMapper.map(accountDto, Account.class);
		account.setPassword(passwordEncoder.encode(account.getPassword()));

		userService.createUser(account);

		return "redirect:/";
	}

	@GetMapping(value = "/mypage")
	public String myPage(@AuthenticationPrincipal Account account, Authentication authentication, Principal principal) {
		String username = account.getUsername();
		System.out.println("username = " + username);

		account = (Account) authentication.getPrincipal();
		username = account.getUsername();
		System.out.println("username = " + username);

		account = (Account)((UsernamePasswordAuthenticationToken)principal).getPrincipal();
		username = account.getUsername();
		System.out.println("username = " + username);

		account = (Account) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		username = account.getUsername();
		System.out.println("username = " + username);

		return "user/mypage";
	}

}
