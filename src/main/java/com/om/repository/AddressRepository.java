package com.om.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.om.modal.Address;

public interface AddressRepository extends JpaRepository<Address, Long> {

}
