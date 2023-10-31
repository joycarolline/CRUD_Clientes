package br.com.taking.clientesrestapi.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import br.com.taking.clientesrestapi.model.Cliente;

public interface ClienteRepository extends JpaRepository<Cliente, Integer>{

	Cliente findByCpf(String cpf);
	
}
