package br.com.taking.clientesrestapi.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import br.com.taking.clientesrestapi.model.Cliente;
import br.com.taking.clientesrestapi.service.ClienteCpfDuplicadoException;
import br.com.taking.clientesrestapi.service.ClienteService;

@CrossOrigin (origins = "http//localhost:3000", allowCredentials = "true")
@RestController
public class ClienteController {
	
	@Autowired
	private ClienteService service;
	
	@RequestMapping(value = "/cliente", method = RequestMethod.POST)
	public ResponseEntity<Object> Post(@RequestBody Cliente cliente){
		
		Cliente clienteIncluido = service.incluir(cliente);
		
		if(clienteIncluido != null) {
			return new ResponseEntity<Object>(clienteIncluido, HttpStatus.OK);
		} else {
			return new ResponseEntity<Object>("CPF ja cadastrado!", HttpStatus.BAD_REQUEST);
		}

	}
	
	@RequestMapping(value = "/cliente/{idUrl}", method = RequestMethod.PUT)
	public ResponseEntity<Object> Put(@PathVariable(value = "idUrl") int id, 
			@RequestBody Cliente newCliente){
		
		try {
			
			Cliente clienteAtualizado = service.atualizar(id, newCliente);
			
			if(clienteAtualizado != null) {
				return new ResponseEntity<Object>(clienteAtualizado, HttpStatus.OK);
			} else {
				return new ResponseEntity<Object>("Cliente nao existente", HttpStatus.NOT_FOUND);
			}		
			
			
		} catch (ClienteCpfDuplicadoException e) {
			e.printStackTrace();
			
			return new ResponseEntity<Object>("CPF ja cadastrado!", HttpStatus.BAD_REQUEST);			
			
		}
		
	}
	
	@RequestMapping(value = "/cliente/{idUrl}", method = RequestMethod.GET)
	public ResponseEntity<Cliente> Get(@PathVariable(value = "idUrl") int id){
		
		Cliente clienteObtido = service.obterPorId(id);
		
		if(clienteObtido != null) {
			return new ResponseEntity<Cliente>(clienteObtido, HttpStatus.OK);
		} else {
			return new ResponseEntity<>(HttpStatus.NOT_FOUND);
		}
		
	}
	
	@RequestMapping(value = "/api/cliente/", method = RequestMethod.GET)
	@PreAuthorize("hasAuthority('OPERACAO')")
	public ResponseEntity<List<Cliente>> GetAll(){
		
		List<Cliente> resultado = service.obterTodos();
		
		return new ResponseEntity<List<Cliente>>(resultado, HttpStatus.OK);
		
	}
	
	@RequestMapping(value = "/api/cliente/{id}", method = RequestMethod.DELETE)
	public ResponseEntity<Object> Delete(@PathVariable(value = "id") int id){
		Cliente cliente = service.obterPorId(id);
		if(cliente != null) {
			service.remover(id);
			return new ResponseEntity<>(HttpStatus.OK);
		} else {
			return new ResponseEntity<>(HttpStatus.NOT_FOUND);
		}	
	}
}
