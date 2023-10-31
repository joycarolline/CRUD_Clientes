package br.com.taking.clientesrestapi.repository;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import br.com.taking.clientesrestapi.model.Usuario;


public interface UsuarioRepository extends JpaRepository<Usuario, Integer>{
	
	Optional<Usuario> findByUsername(String username);
	
	Boolean existsByUsername(String username);
	
	Boolean existsByEmail(String email);

}
