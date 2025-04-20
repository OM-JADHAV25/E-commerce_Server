package com.om.service;

import com.om.exception.ProductException;
import com.om.modal.Cart;
import com.om.modal.CartItem;
import com.om.modal.User;
import com.om.request.AddItemRequest;

public interface CartService {
	
	public Cart createCart(User user);
	
	public CartItem addCartItem(Long userId,AddItemRequest req) throws ProductException;
	
	public Cart findUserCart(Long userId);

}
