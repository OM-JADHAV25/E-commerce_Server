package com.om.service;

import java.util.List;

import com.om.exception.ProductException;
import com.om.modal.Rating;
import com.om.modal.User;
import com.om.request.RatingRequest;

public interface RatingServices {
	
	public Rating createRating(RatingRequest req,User user) throws ProductException;
	
	public List<Rating> getProductsRating(Long productId);

}
