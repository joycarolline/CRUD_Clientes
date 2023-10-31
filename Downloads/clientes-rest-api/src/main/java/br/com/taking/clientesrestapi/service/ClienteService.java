package br.com.taking.clientesrestapi.service;

import java.util.List;

import br.com.taking.clientesrestapi.model.Cliente;

public interface ClienteService {
	
	Cliente incluir(Cliente cliente);
	
	Cliente atualizar(int id, Cliente cliente) throws ClienteCpfDuplicadoException;
	
	Cliente obterPorId(int id);
	
	List<Cliente> obterTodos();
	
	void remover(int id);

}
