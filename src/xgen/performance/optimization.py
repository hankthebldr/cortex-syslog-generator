"""
Performance Optimization Module

This module provides enterprise-scale performance optimizations for log generation
including multi-threading, batch processing, memory optimization, and caching.
"""

import asyncio
import threading
import multiprocessing
import queue
import time
import json
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Callable, Iterator, Tuple
from dataclasses import dataclass, field
import logging
import psutil
import gc
from collections import deque
import hashlib

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class PerformanceMetrics:
    """Performance metrics tracking."""
    logs_generated: int = 0
    generation_time: float = 0.0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    cache_hits: int = 0
    cache_misses: int = 0
    threads_active: int = 0
    throughput_logs_per_second: float = 0.0
    average_log_size_bytes: float = 0.0

@dataclass
class OptimizationConfig:
    """Configuration for performance optimizations."""
    # Threading
    max_threads: int = min(32, (multiprocessing.cpu_count() * 2) + 1)
    use_thread_pool: bool = True
    
    # Batch Processing
    batch_size: int = 1000
    max_batch_memory_mb: int = 100
    
    # Caching
    enable_cache: bool = True
    cache_size_mb: int = 50
    cache_ttl_seconds: int = 3600
    
    # Memory Management
    enable_memory_optimization: bool = True
    gc_threshold: int = 10000  # logs before garbage collection
    max_memory_usage_mb: int = 1024
    
    # Async Processing
    enable_async: bool = True
    async_queue_size: int = 10000
    
    # Streaming
    enable_streaming: bool = False
    stream_buffer_size: int = 1000

class LogGenerationCache:
    """High-performance cache for generated log templates and patterns."""
    
    def __init__(self, max_size_mb: int = 50, ttl_seconds: int = 3600):
        self.max_size_mb = max_size_mb
        self.ttl_seconds = ttl_seconds
        self.cache = {}
        self.access_times = deque()
        self.current_size_bytes = 0
        self._lock = threading.RLock()
        
    def _generate_key(self, vendor: str, ttp_id: str, format_type: str, custom_hash: str = "") -> str:
        """Generate cache key from parameters."""
        key_data = f"{vendor}:{ttp_id}:{format_type}:{custom_hash}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def get(self, key: str) -> Optional[Any]:
        """Get item from cache with TTL check."""
        with self._lock:
            if key in self.cache:
                data, timestamp = self.cache[key]
                if time.time() - timestamp < self.ttl_seconds:
                    self.access_times.append((key, time.time()))
                    return data
                else:
                    # Expired, remove
                    self._remove_key(key)
            return None
    
    def set(self, key: str, value: Any) -> None:
        """Set item in cache with size management."""
        with self._lock:
            # Calculate size of new item
            item_size = len(str(value).encode('utf-8'))
            
            # Check if we need to make space
            while (self.current_size_bytes + item_size) > (self.max_size_mb * 1024 * 1024):
                if not self._evict_lru():
                    break  # Cache empty, can't evict more
            
            # Add new item
            self.cache[key] = (value, time.time())
            self.current_size_bytes += item_size
            self.access_times.append((key, time.time()))
    
    def _remove_key(self, key: str) -> None:
        """Remove key and update size tracking."""
        if key in self.cache:
            data, _ = self.cache[key]
            item_size = len(str(data).encode('utf-8'))
            del self.cache[key]
            self.current_size_bytes -= item_size
    
    def _evict_lru(self) -> bool:
        """Evict least recently used item."""
        if not self.access_times:
            return False
            
        # Find oldest access
        oldest_key = None
        oldest_time = float('inf')
        
        for key, access_time in self.access_times:
            if key in self.cache and access_time < oldest_time:
                oldest_time = access_time
                oldest_key = key
        
        if oldest_key:
            self._remove_key(oldest_key)
            # Remove from access_times
            self.access_times = deque((k, t) for k, t in self.access_times if k != oldest_key)
            return True
        
        return False
    
    def clear(self) -> None:
        """Clear all cache entries."""
        with self._lock:
            self.cache.clear()
            self.access_times.clear()
            self.current_size_bytes = 0

class BatchProcessor:
    """High-performance batch processor for log generation."""
    
    def __init__(self, config: OptimizationConfig):
        self.config = config
        self.batch_queue = queue.Queue(maxsize=config.async_queue_size)
        self.results_queue = queue.Queue()
        self.metrics = PerformanceMetrics()
        
    def process_batch(self, log_requests: List[Dict[str, Any]], 
                     generator_func: Callable) -> List[Any]:
        """Process a batch of log generation requests."""
        batch_start = time.time()
        results = []
        
        # Memory check before processing
        if self.config.enable_memory_optimization:
            memory_usage = psutil.Process().memory_info().rss / 1024 / 1024
            if memory_usage > self.config.max_memory_usage_mb:
                logger.warning(f"High memory usage detected: {memory_usage:.1f}MB")
                gc.collect()  # Force garbage collection
        
        try:
            if self.config.use_thread_pool:
                results = self._process_batch_threaded(log_requests, generator_func)
            else:
                results = self._process_batch_sequential(log_requests, generator_func)
                
        except Exception as e:
            logger.error(f"Batch processing error: {e}")
            raise
        
        # Update metrics
        batch_time = time.time() - batch_start
        self.metrics.logs_generated += len(results)
        self.metrics.generation_time += batch_time
        self.metrics.throughput_logs_per_second = len(results) / batch_time if batch_time > 0 else 0
        
        return results
    
    def _process_batch_threaded(self, log_requests: List[Dict[str, Any]], 
                              generator_func: Callable) -> List[Any]:
        """Process batch using thread pool."""
        results = []
        
        with ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
            # Submit all tasks
            future_to_request = {
                executor.submit(generator_func, **request): request 
                for request in log_requests
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_request):
                try:
                    result = future.result(timeout=30)  # 30 second timeout per log
                    results.append(result)
                except Exception as e:
                    logger.error(f"Thread execution error: {e}")
                    # Continue processing other requests
                    
        return results
    
    def _process_batch_sequential(self, log_requests: List[Dict[str, Any]], 
                                generator_func: Callable) -> List[Any]:
        """Process batch sequentially."""
        results = []
        
        for request in log_requests:
            try:
                result = generator_func(**request)
                results.append(result)
            except Exception as e:
                logger.error(f"Sequential processing error: {e}")
                continue
                
        return results

class AsyncLogGenerator:
    """Asynchronous log generator for high-throughput scenarios."""
    
    def __init__(self, config: OptimizationConfig):
        self.config = config
        self.cache = LogGenerationCache(config.cache_size_mb, config.cache_ttl_seconds)
        self.batch_processor = BatchProcessor(config)
        self.metrics = PerformanceMetrics()
        self._semaphore = asyncio.Semaphore(config.max_threads)
        
    async def generate_logs_async(self, requests: List[Dict[str, Any]], 
                                generator_func: Callable) -> List[Any]:
        """Generate logs asynchronously with optimizations."""
        start_time = time.time()
        
        # Split requests into batches
        batches = self._create_batches(requests)
        
        # Process batches concurrently
        tasks = []
        for batch in batches:
            task = asyncio.create_task(self._process_batch_async(batch, generator_func))
            tasks.append(task)
        
        # Wait for all batches to complete
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Flatten results
        all_results = []
        for result in batch_results:
            if isinstance(result, Exception):
                logger.error(f"Batch processing failed: {result}")
                continue
            all_results.extend(result)
        
        # Update metrics
        total_time = time.time() - start_time
        self.metrics.logs_generated = len(all_results)
        self.metrics.generation_time = total_time
        self.metrics.throughput_logs_per_second = len(all_results) / total_time if total_time > 0 else 0
        
        return all_results
    
    async def _process_batch_async(self, batch: List[Dict[str, Any]], 
                                 generator_func: Callable) -> List[Any]:
        """Process a batch asynchronously."""
        async with self._semaphore:
            # Run batch processing in executor to avoid blocking
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None, 
                self.batch_processor.process_batch, 
                batch, 
                generator_func
            )
    
    def _create_batches(self, requests: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
        """Split requests into optimally-sized batches."""
        batches = []
        current_batch = []
        current_batch_size = 0
        
        for request in requests:
            # Estimate size of request (rough approximation)
            request_size = len(str(request)) * 100  # Assume 100x expansion for generated log
            
            # Check if adding this request would exceed batch limits
            if (len(current_batch) >= self.config.batch_size or 
                (current_batch_size + request_size) > (self.config.max_batch_memory_mb * 1024 * 1024)):
                
                if current_batch:  # Don't add empty batches
                    batches.append(current_batch)
                    current_batch = []
                    current_batch_size = 0
            
            current_batch.append(request)
            current_batch_size += request_size
        
        # Add final batch
        if current_batch:
            batches.append(current_batch)
        
        return batches

class StreamingLogGenerator:
    """Streaming log generator for real-time scenarios."""
    
    def __init__(self, config: OptimizationConfig):
        self.config = config
        self.buffer = deque(maxlen=config.stream_buffer_size)
        self.is_streaming = False
        self._lock = threading.RLock()
        
    def start_stream(self, generator_func: Callable, 
                    generation_params: Dict[str, Any]) -> Iterator[Any]:
        """Start streaming log generation."""
        self.is_streaming = True
        
        def generate_stream():
            while self.is_streaming:
                try:
                    # Generate a log
                    log = generator_func(**generation_params)
                    
                    with self._lock:
                        self.buffer.append(log)
                    
                    yield log
                    
                    # Small delay to prevent overwhelming
                    time.sleep(0.001)  # 1ms
                    
                except Exception as e:
                    logger.error(f"Stream generation error: {e}")
                    break
        
        return generate_stream()
    
    def stop_stream(self):
        """Stop streaming generation."""
        self.is_streaming = False
    
    def get_buffered_logs(self) -> List[Any]:
        """Get all buffered logs."""
        with self._lock:
            logs = list(self.buffer)
            self.buffer.clear()
            return logs

class PerformanceOptimizer:
    """Main performance optimization coordinator."""
    
    def __init__(self, config: Optional[OptimizationConfig] = None):
        self.config = config or OptimizationConfig()
        self.cache = LogGenerationCache(
            self.config.cache_size_mb, 
            self.config.cache_ttl_seconds
        ) if self.config.enable_cache else None
        
        self.batch_processor = BatchProcessor(self.config)
        self.async_generator = AsyncLogGenerator(self.config)
        self.streaming_generator = StreamingLogGenerator(self.config)
        self.metrics = PerformanceMetrics()
        
        # Performance monitoring
        self._monitor_thread = None
        self._monitoring = False
        
    def optimize_generation(self, requests: List[Dict[str, Any]], 
                          generator_func: Callable) -> List[Any]:
        """Main optimization entry point."""
        start_time = time.time()
        
        # Choose optimal generation strategy based on request volume
        if len(requests) > 10000 and self.config.enable_async:
            # Use async generation for large volumes
            return asyncio.run(
                self.async_generator.generate_logs_async(requests, generator_func)
            )
        elif len(requests) > 100:
            # Use batch processing for medium volumes
            return self.batch_processor.process_batch(requests, generator_func)
        else:
            # Use sequential processing for small volumes
            return self._generate_sequential(requests, generator_func)
    
    def _generate_sequential(self, requests: List[Dict[str, Any]], 
                           generator_func: Callable) -> List[Any]:
        """Generate logs sequentially with caching."""
        results = []
        
        for request in requests:
            # Check cache if enabled
            if self.cache:
                cache_key = self._generate_cache_key(request)
                cached_result = self.cache.get(cache_key)
                
                if cached_result:
                    self.metrics.cache_hits += 1
                    results.append(cached_result)
                    continue
                else:
                    self.metrics.cache_misses += 1
            
            # Generate new log
            try:
                result = generator_func(**request)
                results.append(result)
                
                # Cache result if enabled
                if self.cache:
                    self.cache.set(cache_key, result)
                    
            except Exception as e:
                logger.error(f"Sequential generation error: {e}")
                continue
        
        return results
    
    def _generate_cache_key(self, request: Dict[str, Any]) -> str:
        """Generate cache key for request."""
        # Create a hash of the request parameters
        key_data = json.dumps(request, sort_keys=True)
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def start_performance_monitoring(self):
        """Start performance monitoring thread."""
        if not self._monitoring:
            self._monitoring = True
            self._monitor_thread = threading.Thread(
                target=self._monitor_performance, 
                daemon=True
            )
            self._monitor_thread.start()
    
    def stop_performance_monitoring(self):
        """Stop performance monitoring."""
        self._monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=1)
    
    def _monitor_performance(self):
        """Monitor system performance metrics."""
        while self._monitoring:
            try:
                # CPU and memory monitoring
                process = psutil.Process()
                self.metrics.cpu_usage_percent = process.cpu_percent()
                self.metrics.memory_usage_mb = process.memory_info().rss / 1024 / 1024
                
                # Thread monitoring
                self.metrics.threads_active = threading.active_count()
                
                # Log performance warnings
                if self.metrics.memory_usage_mb > self.config.max_memory_usage_mb * 0.8:
                    logger.warning(f"High memory usage: {self.metrics.memory_usage_mb:.1f}MB")
                
                if self.metrics.cpu_usage_percent > 80:
                    logger.warning(f"High CPU usage: {self.metrics.cpu_usage_percent:.1f}%")
                
                time.sleep(5)  # Monitor every 5 seconds
                
            except Exception as e:
                logger.error(f"Performance monitoring error: {e}")
                time.sleep(5)
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Get comprehensive performance report."""
        return {
            "metrics": {
                "logs_generated": self.metrics.logs_generated,
                "generation_time_seconds": self.metrics.generation_time,
                "throughput_logs_per_second": self.metrics.throughput_logs_per_second,
                "memory_usage_mb": self.metrics.memory_usage_mb,
                "cpu_usage_percent": self.metrics.cpu_usage_percent,
                "cache_hit_rate": (
                    self.metrics.cache_hits / (self.metrics.cache_hits + self.metrics.cache_misses)
                    if (self.metrics.cache_hits + self.metrics.cache_misses) > 0 else 0
                ),
                "threads_active": self.metrics.threads_active
            },
            "config": {
                "max_threads": self.config.max_threads,
                "batch_size": self.config.batch_size,
                "cache_enabled": self.config.enable_cache,
                "async_enabled": self.config.enable_async,
                "memory_optimization": self.config.enable_memory_optimization
            },
            "recommendations": self._generate_performance_recommendations()
        }
    
    def _generate_performance_recommendations(self) -> List[str]:
        """Generate performance optimization recommendations."""
        recommendations = []
        
        # Memory recommendations
        if self.metrics.memory_usage_mb > self.config.max_memory_usage_mb * 0.7:
            recommendations.append("Consider reducing batch size or enabling memory optimization")
        
        # Cache recommendations
        if self.config.enable_cache:
            hit_rate = (
                self.metrics.cache_hits / (self.metrics.cache_hits + self.metrics.cache_misses)
                if (self.metrics.cache_hits + self.metrics.cache_misses) > 0 else 0
            )
            if hit_rate < 0.3:
                recommendations.append("Low cache hit rate - consider increasing cache size or TTL")
        else:
            recommendations.append("Enable caching to improve performance for repeated requests")
        
        # Threading recommendations
        if self.metrics.threads_active > self.config.max_threads * 0.9:
            recommendations.append("Consider increasing max_threads for better parallelization")
        
        # Throughput recommendations
        if self.metrics.throughput_logs_per_second < 100:
            recommendations.append("Low throughput detected - consider enabling async processing")
        
        return recommendations
    
    def optimize_config_for_workload(self, expected_logs_per_hour: int, 
                                   average_log_size_kb: float) -> OptimizationConfig:
        """Auto-optimize configuration based on expected workload."""
        config = OptimizationConfig()
        
        # Adjust based on volume
        if expected_logs_per_hour > 100000:  # High volume
            config.max_threads = min(64, multiprocessing.cpu_count() * 4)
            config.batch_size = 5000
            config.enable_async = True
            config.cache_size_mb = 200
            
        elif expected_logs_per_hour > 10000:  # Medium volume
            config.max_threads = min(32, multiprocessing.cpu_count() * 2)
            config.batch_size = 2000
            config.enable_async = True
            config.cache_size_mb = 100
            
        else:  # Low volume
            config.max_threads = min(16, multiprocessing.cpu_count())
            config.batch_size = 500
            config.enable_async = False
            config.cache_size_mb = 50
        
        # Adjust based on log size
        if average_log_size_kb > 10:  # Large logs
            config.batch_size = int(config.batch_size * 0.5)  # Smaller batches
            config.max_batch_memory_mb = 200
        
        return config

# Convenience functions
def create_optimized_config(workload: str = "medium") -> OptimizationConfig:
    """Create an optimized configuration for different workload types."""
    configs = {
        "light": OptimizationConfig(
            max_threads=8,
            batch_size=100,
            enable_async=False,
            cache_size_mb=25
        ),
        "medium": OptimizationConfig(),  # Default config
        "heavy": OptimizationConfig(
            max_threads=64,
            batch_size=5000,
            enable_async=True,
            cache_size_mb=200,
            max_memory_usage_mb=2048
        ),
        "enterprise": OptimizationConfig(
            max_threads=128,
            batch_size=10000,
            enable_async=True,
            cache_size_mb=500,
            max_memory_usage_mb=4096,
            enable_streaming=True
        )
    }
    
    return configs.get(workload, OptimizationConfig())

# Export main classes and functions
__all__ = [
    "PerformanceOptimizer", "OptimizationConfig", "PerformanceMetrics",
    "LogGenerationCache", "BatchProcessor", "AsyncLogGenerator", 
    "StreamingLogGenerator", "create_optimized_config"
]