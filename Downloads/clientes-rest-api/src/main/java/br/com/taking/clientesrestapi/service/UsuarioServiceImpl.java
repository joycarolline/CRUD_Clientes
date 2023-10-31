package br.com.taking.clientesrestapi.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import br.com.taking.clientesrestapi.model.EPerfil;
import br.com.taking.clientesrestapi.model.Perfil;
import br.com.taking.clientesrestapi.model.Usuario;
import br.com.taking.clientesrestapi.repository.PerfilRepository;
import br.com.taking.clientesrestapi.repository.UsuarioRepository;
import br.com.taking.clientesrestapi.security.request.SignUpRequest;
import br.com.taking.clientesrestapi.service.exception.UserNameOrEmailExistentException;

@Service
public class UsuarioServiceImpl implements UsuarioService, UserDetailsService{
	
	@Autowired
	private UsuarioRepository repository;
	
	@Autowired
	private PerfilRepository perfilRepository;
	
	@Autowired
	private PasswordEncoder encoder;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

		Optional<Usuario> optUsuario = repository.findByUsername(username);
		
		if(optUsuario.isPresent()) {
			return optUsuario.get();
		} else {
			throw new UsernameNotFoundException("Username não encontrado");
		}
		
	}

	@Override
	public void registrarUsuario(SignUpRequest request) throws UserNameOrEmailExistentException {
		// TODO Auto-generated method stub
		
		if (repository.existsByUsername(request.getUsername())) {
			
			throw new UserNameOrEmailExistentException();
		}
		
		if(repository.existsByEmail(request.getEmail())) {
			
			throw new UserNameOrEmailExistentException();
		}
		
		
		Usuario usuario = new Usuario();
		usuario.setUsername(request.getUsername());
		usuario.setEmail(request.getEmail());
		usuario.setNome(request.getNome());
		usuario.setPassword(encoder.encode(request.getPassword()));
		
		Optional<Perfil> optPerfil = perfilRepository.findByNome(EPerfil.OPERACAO);
		if(optPerfil.isPresent());  {
			usuario.getPerfis().add(optPerfil.get());
		}
		
		repository.save(usuario);
		
		
	}

}
