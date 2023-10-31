package br.com.taking.clientesrestapi.service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.com.taking.clientesrestapi.model.Cliente;
import br.com.taking.clientesrestapi.repository.ClienteRepository;

@Service
public class ClienteServiceImpl implements ClienteService{

	@Autowired
	private ClienteRepository repository;
	 
	
	@Override
	public Cliente incluir(Cliente cliente) {
		
		//TODO: verificacao de unicidade de CPF
		String cpf = cliente.getCpf();
		
		Cliente clienteComMesmoCPF = repository.findByCpf(cpf);
		
		if(clienteComMesmoCPF == null) {
			return repository.save(cliente);	
		} else {
			return null;
		}
		
	}


	@Override
	public Cliente atualizar(int id, Cliente cliente) throws ClienteCpfDuplicadoException {

		Optional<Cliente> resultFromDB = repository.findById(id);
		if(resultFromDB.isPresent()) {
			Cliente clienteFromDB = resultFromDB.get();
			
			String cpf = cliente.getCpf();			
			Cliente clienteComMesmoCPF = repository.findByCpf(cpf);
			
			if(clienteComMesmoCPF != null 
					&& clienteComMesmoCPF.getId() != clienteFromDB.getId()) {
				
				throw new ClienteCpfDuplicadoException();			
				
			}
			
			clienteFromDB.setCpf(cliente.getCpf());
			clienteFromDB.setNome(cliente.getNome());
			clienteFromDB.setEmail(cliente.getEmail());
			clienteFromDB.setCelular(cliente.getCelular());
			
			return repository.save(clienteFromDB);			
		} else {
			return null;
		}		
	}


	@Override
	public Cliente obterPorId(int id) {
	
		Optional<Cliente> resultFromDB = repository.findById(id);
		
		if(resultFromDB.isPresent()) {
			return resultFromDB.get();
		} else {
			return null;
		}
		
	}


	@Override
	public List<Cliente> obterTodos() {

		return repository.findAll();
		
	}


	@Override
	public void remover(int id) {
		
		repository.deleteById(id);
		
	}
	
	
}
