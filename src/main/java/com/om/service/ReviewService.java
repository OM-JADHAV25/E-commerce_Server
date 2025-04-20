package com.om.service;

import java.util.List;

import com.om.exception.ProductException;
import com.om.modal.Review;
import com.om.modal.User;
import com.om.request.ReviewRequest;

public interface ReviewService {

	public Review createReview(ReviewRequest req,User user) throws ProductException;
	
	public List<Review> getAllReview(Long productId);
	
	
}
