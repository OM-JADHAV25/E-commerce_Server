package com.om.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.om.modal.OrderItem;

public interface OrderItemRepository extends JpaRepository<OrderItem, Long> {

}
