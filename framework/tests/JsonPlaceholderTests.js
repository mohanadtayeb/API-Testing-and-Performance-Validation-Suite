const BaseTest = require('../src/BaseTest');
const ApiClient = require('../src/ApiClient');
const { getInstance: getConfig } = require('../src/ConfigManager');

/**
 * JSONPlaceholder API Test Suite
 * Tests CRUD operations and data validation
 */
class JsonPlaceholderTests extends BaseTest {
  constructor() {
    super('JSONPlaceholder API Tests', 'Comprehensive testing of JSONPlaceholder API endpoints');
    
    const config = getConfig();
    const apiConfig = config.getApiConfig('jsonplaceholder');
    
    this.client = new ApiClient(apiConfig);
    this.addTag('api');
    this.addTag('crud');
    this.addTag('jsonplaceholder');
  }

  async execute() {
    await this.testGetAllPosts();
    await this.testGetSinglePost();
    await this.testGetNonExistentPost();
    await this.testCreatePost();
    await this.testUpdatePost();
    await this.testDeletePost();
    await this.testGetAllUsers();
    await this.testUserValidation();
    await this.testCommentsForPost();
    await this.testQueryParameters();
  }

  async testGetAllPosts() {
    console.log('  Testing: Get all posts');
    
    const response = await this.client.get('/posts');
    
    this.assertStatusCode(response, 200, 'Should return 200 OK');
    this.assertTrue(Array.isArray(response.data), 'Response should be an array');
    this.assertEqual(response.data.length, 100, 'Should return 100 posts');
    this.assertResponseTime(response, 2000, 'Response time should be under 2 seconds');
    
    // Validate post structure
    if (response.data.length > 0) {
      const firstPost = response.data[0];
      this.assertNotNull(firstPost.userId, 'Post should have userId');
      this.assertNotNull(firstPost.id, 'Post should have id');
      this.assertNotNull(firstPost.title, 'Post should have title');
      this.assertNotNull(firstPost.body, 'Post should have body');
      
      // Store for later tests
      this.setData('firstPostId', firstPost.id);
      this.setData('firstPostUserId', firstPost.userId);
    }
  }

  async testGetSinglePost() {
    console.log('  Testing: Get single post');
    
    const postId = this.getData('firstPostId') || 1;
    const response = await this.client.get(`/posts/${postId}`);
    
    this.assertStatusCode(response, 200, 'Should return 200 OK');
    this.assertEqual(response.data.id, postId, 'Returned post ID should match requested ID');
    
    // Validate response structure
    const expectedStructure = {
      userId: 'number',
      id: 'number',
      title: 'string',
      body: 'string'
    };
    this.assertJsonStructure(response, expectedStructure, 'Post should have correct structure');
  }

  async testGetNonExistentPost() {
    console.log('  Testing: Get non-existent post');
    
    try {
      const response = await this.client.get('/posts/999');
      this.assertStatusCode(response, 404, 'Should return 404 for non-existent post');
    } catch (error) {
      if (error.response && error.response.status === 404) {
        this.assertTrue(true, 'Correctly returned 404 for non-existent post');
      } else {
        throw error;
      }
    }
  }

  async testCreatePost() {
    console.log('  Testing: Create new post');
    
    const newPost = {
      title: 'Test Post Title',
      body: 'This is a test post created by automated testing',
      userId: 1
    };
    
    const response = await this.client.post('/posts', newPost);
    
    this.assertStatusCode(response, 201, 'Should return 201 Created');
    this.assertEqual(response.data.title, newPost.title, 'Title should match');
    this.assertEqual(response.data.body, newPost.body, 'Body should match');
    this.assertEqual(response.data.userId, newPost.userId, 'UserId should match');
    this.assertNotNull(response.data.id, 'Created post should have an ID');
    
    // Store created post ID for other tests
    this.setData('createdPostId', response.data.id);
  }

  async testUpdatePost() {
    console.log('  Testing: Update post');
    
    // Use a valid post ID (1) since JSONPlaceholder is a fake API
    const postId = 1;
    const updatedPost = {
      id: postId,
      title: 'Updated Test Post Title',
      body: 'This post has been updated via automated testing',
      userId: 1
    };
    
    const response = await this.client.put(`/posts/${postId}`, updatedPost);
    
    this.assertStatusCode(response, 200, 'Should return 200 OK');
    this.assertEqual(response.data.title, updatedPost.title, 'Title should be updated');
    this.assertEqual(response.data.body, updatedPost.body, 'Body should be updated');
    this.assertEqual(response.data.id, postId, 'ID should remain the same');
  }

  async testDeletePost() {
    console.log('  Testing: Delete post');
    
    // Use a valid post ID (1) since JSONPlaceholder is a fake API
    const postId = 1;
    const response = await this.client.delete(`/posts/${postId}`);
    
    this.assertStatusCode(response, 200, 'Should return 200 OK');
    
    // For JSONPlaceholder, the response body should be empty object
    if (typeof response.data === 'object' && Object.keys(response.data).length === 0) {
      this.assertTrue(true, 'Delete should return empty object');
    }
  }

  async testGetAllUsers() {
    console.log('  Testing: Get all users');
    
    const response = await this.client.get('/users');
    
    this.assertStatusCode(response, 200, 'Should return 200 OK');
    this.assertTrue(Array.isArray(response.data), 'Response should be an array');
    this.assertEqual(response.data.length, 10, 'Should return 10 users');
    
    // Validate user structure
    if (response.data.length > 0) {
      const firstUser = response.data[0];
      this.assertNotNull(firstUser.id, 'User should have id');
      this.assertNotNull(firstUser.name, 'User should have name');
      this.assertNotNull(firstUser.username, 'User should have username');
      this.assertNotNull(firstUser.email, 'User should have email');
      this.assertNotNull(firstUser.address, 'User should have address');
      this.assertNotNull(firstUser.phone, 'User should have phone');
      this.assertNotNull(firstUser.website, 'User should have website');
      this.assertNotNull(firstUser.company, 'User should have company');
    }
  }

  async testUserValidation() {
    console.log('  Testing: User data validation');
    
    const response = await this.client.get('/users/1');
    
    this.assertStatusCode(response, 200, 'Should return 200 OK');
    
    const user = response.data;
    
    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    this.assertTrue(emailRegex.test(user.email), 'Email should be in valid format');
    
    // Address structure validation
    this.assertNotNull(user.address.street, 'Address should have street');
    this.assertNotNull(user.address.city, 'Address should have city');
    this.assertNotNull(user.address.zipcode, 'Address should have zipcode');
    this.assertNotNull(user.address.geo, 'Address should have geo coordinates');
    
    // Geo coordinates validation
    const lat = parseFloat(user.address.geo.lat);
    const lng = parseFloat(user.address.geo.lng);
    this.assertTrue(lat >= -90 && lat <= 90, 'Latitude should be between -90 and 90');
    this.assertTrue(lng >= -180 && lng <= 180, 'Longitude should be between -180 and 180');
    
    // Company structure validation
    this.assertNotNull(user.company.name, 'Company should have name');
    this.assertNotNull(user.company.catchPhrase, 'Company should have catchPhrase');
    this.assertNotNull(user.company.bs, 'Company should have bs');
  }

  async testCommentsForPost() {
    console.log('  Testing: Get comments for post');
    
    const postId = this.getData('firstPostId') || 1;
    const response = await this.client.get(`/posts/${postId}/comments`);
    
    this.assertStatusCode(response, 200, 'Should return 200 OK');
    this.assertTrue(Array.isArray(response.data), 'Response should be an array');
    
    // Validate comment structure
    if (response.data.length > 0) {
      const firstComment = response.data[0];
      this.assertEqual(firstComment.postId, postId, 'Comment should belong to correct post');
      this.assertNotNull(firstComment.id, 'Comment should have id');
      this.assertNotNull(firstComment.name, 'Comment should have name');
      this.assertNotNull(firstComment.email, 'Comment should have email');
      this.assertNotNull(firstComment.body, 'Comment should have body');
      
      // Email validation in comments
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      this.assertTrue(emailRegex.test(firstComment.email), 'Comment email should be in valid format');
    }
  }

  async testQueryParameters() {
    console.log('  Testing: Query parameters');
    
    const userId = this.getData('firstPostUserId') || 1;
    
    // Test filtering posts by userId
    const response = await this.client.get(`/posts?userId=${userId}`);
    
    this.assertStatusCode(response, 200, 'Should return 200 OK');
    this.assertTrue(Array.isArray(response.data), 'Response should be an array');
    
    // Validate that all returned posts belong to the specified user
    if (response.data.length > 0) {
      const allPostsBelongToUser = response.data.every(post => post.userId === userId);
      this.assertTrue(allPostsBelongToUser, 'All posts should belong to the specified user');
    }
    
    // Test limiting results
    const limitedResponse = await this.client.get('/posts?_limit=5');
    this.assertStatusCode(limitedResponse, 200, 'Should return 200 OK');
    this.assertEqual(limitedResponse.data.length, 5, 'Should return exactly 5 posts');
  }

  async cleanup() {
    await super.cleanup();
    console.log('  JSONPlaceholder tests completed');
  }
}

module.exports = JsonPlaceholderTests;