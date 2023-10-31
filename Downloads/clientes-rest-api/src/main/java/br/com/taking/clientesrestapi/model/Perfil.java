package br.com.taking.clientesrestapi.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "perfil")
public class Perfil {
	
	@Id
	@Column(name = "id")
	private int id;
	
	@Enumerated(EnumType.STRING)
	@Column(name = "nome")
	private EPerfil nome;

	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

	public EPerfil getNome() {
		return nome;
	}

	public void setNome(EPerfil nome) {
		this.nome = nome;
	}
	
}
