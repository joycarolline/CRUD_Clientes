package br.com.taking.clientesrestapi.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import br.com.taking.clientesrestapi.model.EPerfil;
import br.com.taking.clientesrestapi.model.Perfil;

public interface PerfilRepository extends JpaRepository<Perfil, Integer>{

	Optional<Perfil> findByNome(EPerfil nome);
	
}
