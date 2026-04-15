"""
AI Chunker - Handles chunked processing of large data for AI analysis
Splits large payloads into manageable chunks to prevent timeouts and improve performance
"""

import asyncio
from typing import List, Dict, Any, Callable, Optional
import logging


class AIChunker:
    """Manages chunked processing of large data for AI analysis"""
    
    def __init__(self, chunk_size: int = 2000, max_concurrent: int = 3):
        """
        Initialize AI Chunker
        
        Args:
            chunk_size: Maximum characters per chunk (default 2000)
            max_concurrent: Maximum concurrent AI requests (default 3)
        """
        self.chunk_size = chunk_size
        self.max_concurrent = max_concurrent
        self.logger = logging.getLogger(__name__)
    
    def split_text_into_chunks(self, text: str, overlap: int = 200) -> List[str]:
        """
        Split text into overlapping chunks for context preservation
        
        Args:
            text: Text to split
            overlap: Number of characters to overlap between chunks
            
        Returns:
            List of text chunks
        """
        if len(text) <= self.chunk_size:
            return [text]
        
        chunks = []
        start = 0
        
        while start < len(text):
            end = start + self.chunk_size
            
            # If not the last chunk, try to break at sentence boundary
            if end < len(text):
                # Look for sentence endings near the chunk boundary
                for delimiter in ['. ', '.\n', '! ', '?\n', '\n\n']:
                    last_delimiter = text[start:end].rfind(delimiter)
                    if last_delimiter > self.chunk_size * 0.7:  # At least 70% of chunk size
                        end = start + last_delimiter + len(delimiter)
                        break
            
            chunks.append(text[start:end])
            start = end - overlap  # Overlap for context
        
        return chunks
    
    def split_list_into_chunks(self, items: List[Any], items_per_chunk: int = 10) -> List[List[Any]]:
        """
        Split a list into smaller chunks
        
        Args:
            items: List to split
            items_per_chunk: Number of items per chunk
            
        Returns:
            List of item chunks
        """
        if len(items) <= items_per_chunk:
            return [items]
        
        chunks = []
        for i in range(0, len(items), items_per_chunk):
            chunks.append(items[i:i + items_per_chunk])
        
        return chunks
    
    async def process_chunks_parallel(
        self,
        chunks: List[Any],
        process_func: Callable,
        aggregate_func: Optional[Callable] = None
    ) -> Any:
        """
        Process chunks in parallel with concurrency limit
        
        Args:
            chunks: List of chunks to process
            process_func: Async function to process each chunk
            aggregate_func: Optional function to aggregate results
            
        Returns:
            Aggregated results or list of results
        """
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def process_with_semaphore(chunk, index):
            async with semaphore:
                try:
                    self.logger.info(f"Processing chunk {index + 1}/{len(chunks)}")
                    result = await process_func(chunk, index)
                    return result
                except Exception as e:
                    self.logger.error(f"Error processing chunk {index + 1}: {e}")
                    return None
        
        # Process all chunks with concurrency limit
        tasks = [process_with_semaphore(chunk, i) for i, chunk in enumerate(chunks)]
        results = await asyncio.gather(*tasks)
        
        # Filter out None results (failed chunks)
        results = [r for r in results if r is not None]
        
        # Aggregate results if function provided
        if aggregate_func:
            return aggregate_func(results)
        
        return results
    
    async def process_chunks_sequential(
        self,
        chunks: List[Any],
        process_func: Callable,
        aggregate_func: Optional[Callable] = None,
        delay: float = 0.5
    ) -> Any:
        """
        Process chunks sequentially with delay between requests
        
        Args:
            chunks: List of chunks to process
            process_func: Async function to process each chunk
            aggregate_func: Optional function to aggregate results
            delay: Delay between chunks in seconds
            
        Returns:
            Aggregated results or list of results
        """
        results = []
        
        for i, chunk in enumerate(chunks):
            try:
                self.logger.info(f"Processing chunk {i + 1}/{len(chunks)}")
                result = await process_func(chunk, i)
                if result is not None:
                    results.append(result)
                
                # Add delay between requests (except after last chunk)
                if i < len(chunks) - 1:
                    await asyncio.sleep(delay)
                    
            except Exception as e:
                self.logger.error(f"Error processing chunk {i + 1}: {e}")
                continue
        
        # Aggregate results if function provided
        if aggregate_func:
            return aggregate_func(results)
        
        return results
    
    def create_vulnerability_chunks(
        self,
        vulnerabilities: List[Dict[str, Any]],
        max_per_chunk: int = 5
    ) -> List[List[Dict[str, Any]]]:
        """
        Split vulnerabilities into chunks for analysis
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            max_per_chunk: Maximum vulnerabilities per chunk
            
        Returns:
            List of vulnerability chunks
        """
        return self.split_list_into_chunks(vulnerabilities, max_per_chunk)
    
    def create_payload_chunks(
        self,
        target_info: Dict[str, Any],
        payload_count: int = 50,
        payloads_per_chunk: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Create chunks for payload generation
        
        Args:
            target_info: Target information dictionary
            payload_count: Total payloads to generate
            payloads_per_chunk: Payloads to generate per chunk
            
        Returns:
            List of chunk specifications
        """
        num_chunks = (payload_count + payloads_per_chunk - 1) // payloads_per_chunk
        
        chunks = []
        for i in range(num_chunks):
            chunk_info = target_info.copy()
            chunk_info['chunk_id'] = i
            chunk_info['payloads_requested'] = min(
                payloads_per_chunk,
                payload_count - (i * payloads_per_chunk)
            )
            chunks.append(chunk_info)
        
        return chunks
    
    @staticmethod
    def aggregate_text_results(results: List[str]) -> str:
        """Aggregate text results by joining with newlines"""
        return "\n\n".join(results)
    
    @staticmethod
    def aggregate_list_results(results: List[List[Any]]) -> List[Any]:
        """Aggregate list results by flattening"""
        flattened = []
        for result in results:
            if isinstance(result, list):
                flattened.extend(result)
            else:
                flattened.append(result)
        return flattened
    
    @staticmethod
    def aggregate_dict_results(results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate dictionary results by merging"""
        merged = {}
        for result in results:
            if isinstance(result, dict):
                merged.update(result)
        return merged


# Convenience functions for common use cases

async def analyze_vulnerabilities_chunked(
    vulnerabilities: List[Dict[str, Any]],
    analyze_func: Callable,
    chunk_size: int = 5,
    parallel: bool = False
) -> List[Dict[str, Any]]:
    """
    Analyze vulnerabilities in chunks
    
    Args:
        vulnerabilities: List of vulnerabilities to analyze
        analyze_func: Function to analyze each vulnerability
        chunk_size: Vulnerabilities per chunk
        parallel: Whether to process chunks in parallel
        
    Returns:
        List of analyzed vulnerabilities
    """
    chunker = AIChunker()
    chunks = chunker.create_vulnerability_chunks(vulnerabilities, chunk_size)
    
    async def process_chunk(vuln_chunk, index):
        results = []
        for vuln in vuln_chunk:
            result = await analyze_func(vuln)
            results.append(result)
        return results
    
    if parallel:
        return await chunker.process_chunks_parallel(
            chunks,
            process_chunk,
            AIChunker.aggregate_list_results
        )
    else:
        return await chunker.process_chunks_sequential(
            chunks,
            process_chunk,
            AIChunker.aggregate_list_results
        )


async def generate_payloads_chunked(
    target_info: Dict[str, Any],
    generate_func: Callable,
    total_payloads: int = 50,
    payloads_per_chunk: int = 10,
    parallel: bool = True
) -> List[str]:
    """
    Generate payloads in chunks
    
    Args:
        target_info: Target information
        generate_func: Function to generate payloads
        total_payloads: Total payloads to generate
        payloads_per_chunk: Payloads per chunk
        parallel: Whether to process chunks in parallel
        
    Returns:
        List of generated payloads
    """
    chunker = AIChunker()
    chunks = chunker.create_payload_chunks(
        target_info,
        total_payloads,
        payloads_per_chunk
    )
    
    async def process_chunk(chunk_info, index):
        return await generate_func(chunk_info)
    
    if parallel:
        return await chunker.process_chunks_parallel(
            chunks,
            process_chunk,
            AIChunker.aggregate_list_results
        )
    else:
        return await chunker.process_chunks_sequential(
            chunks,
            process_chunk,
            AIChunker.aggregate_list_results
        )
