"""
Task Scheduler for the SKrulll Orchestrator.

This module provides the core functionality for scheduling and managing tasks,
including interval-based and cron-based tasks.
"""
import json
import logging
import os
import shlex
import subprocess
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Callable

logger = logging.getLogger(__name__)

try:
    import croniter
    CRONITER_AVAILABLE = True
except ImportError:
    logger.warning("croniter not installed, cron-based scheduling will be limited")
    CRONITER_AVAILABLE = False


class Task:
    """
    Represents a scheduled task.
    """
    
    def __init__(self, name: str, command: str, 
                interval: Optional[int] = None, 
                cron: Optional[str] = None,
                description: Optional[str] = None):
        """
        Initialize a task.
        
        Args:
            name: Task name
            command: Command to execute
            interval: Interval in minutes (for interval-based tasks)
            cron: Cron expression (for cron-based tasks)
            description: Task description
        """
        self.name = name
        self.command = command
        self.interval = interval
        self.cron = cron
        self.description = description
        self.next_run = None
        self.last_run = None
        self.status = "scheduled"  # scheduled, running, completed, failed
        self.result = None
        
        # Calculate initial next_run
        self.calculate_next_run()
    
    def calculate_next_run(self):
        """Calculate the next run time based on the schedule."""
        now = datetime.now()
        
        if self.interval is not None:
            # Interval-based (run every N minutes)
            if self.last_run:
                self.next_run = self.last_run + timedelta(minutes=self.interval)
            else:
                self.next_run = now
        elif self.cron is not None and CRONITER_AVAILABLE:
            # Cron-based
            try:
                itr = croniter.croniter(self.cron, now)
                self.next_run = itr.get_next(datetime)
            except Exception as e:
                logger.error(f"Invalid cron expression '{self.cron}': {str(e)}")
                self.next_run = None
        else:
            self.next_run = None
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the task to a dictionary for serialization.
        
        Returns:
            Dictionary representation of the task
        """
        return {
            "name": self.name,
            "command": self.command,
            "interval": self.interval,
            "cron": self.cron,
            "description": self.description,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "status": self.status,
            "result": self.result
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Task':
        """
        Create a task from a dictionary.
        
        Args:
            data: Dictionary containing task data
            
        Returns:
            Task instance
        """
        task = cls(
            name=data["name"],
            command=data["command"],
            interval=data.get("interval"),
            cron=data.get("cron"),
            description=data.get("description")
        )
        
        # Restore saved state
        if data.get("next_run"):
            task.next_run = datetime.fromisoformat(data["next_run"])
        if data.get("last_run"):
            task.last_run = datetime.fromisoformat(data["last_run"])
        task.status = data.get("status", "scheduled")
        task.result = data.get("result")
        
        return task
        
    def should_run(self) -> bool:
        """
        Check if the task should run now.
        
        Returns:
            True if the task should run, False otherwise
        """
        if self.next_run is None:
            return False
            
        now = datetime.now()
        return now >= self.next_run
        
    def execute(self):
        """
        Execute the task.
        
        Returns:
            Task result
        """
        logger.info(f"Executing task '{self.name}': {self.command}")
        
        self.status = "running"
        self.last_run = datetime.now()
        
        try:
            # Execute the command using subprocess with shell=False for security
            # Using shlex.split to properly handle command arguments
            process = subprocess.Popen(
                shlex.split(self.command),
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            stdout, stderr = process.communicate()
            exit_code = process.returncode
            
            result = {
                "exit_code": exit_code,
                "stdout": stdout,
                "stderr": stderr,
                "completed_at": datetime.now().isoformat()
            }
            
            if exit_code == 0:
                self.status = "completed"
                logger.info(f"Task '{self.name}' completed successfully")
            else:
                self.status = "failed"
                logger.error(f"Task '{self.name}' failed with exit code {exit_code}")
                logger.error(f"Error output: {stderr}")
            
            self.result = result
            
            # Calculate next run time
            self.calculate_next_run()
            
            return result
            
        except Exception as e:
            logger.error(f"Error executing task '{self.name}': {str(e)}", exc_info=True)
            
            self.status = "failed"
            self.result = {
                "error": str(e),
                "completed_at": datetime.now().isoformat()
            }
            
            # Calculate next run time
            self.calculate_next_run()
            
            return self.result


class TaskScheduler:
    """
    Manages scheduled tasks and their execution.
    """
    
    def __init__(self, storage_path: Optional[str] = None, auto_start: bool = True):
        """
        Initialize the task scheduler.
        
        Args:
            storage_path: Path to store task data (JSON file)
            auto_start: Whether to automatically start the scheduler
            
        Note:
            For more robust persistence, especially with many tasks or high concurrency
            requirements, consider using a database instead of a JSON file.
        """
        self.tasks = {}  # name -> Task
        self.running = False
        self.thread = None
        self.storage_path = storage_path or "data/scheduler.json"
        
        # Create storage directory if it doesn't exist
        if self.storage_path:
            storage_dir = os.path.dirname(self.storage_path)
            Path(storage_dir).mkdir(parents=True, exist_ok=True)
            
            # Check if the path is writable
            self._check_path_writable(self.storage_path)
        
        # Load existing tasks
        self.load_tasks()
        
        # Start scheduler thread if auto_start is True
        if auto_start:
            self.start()
    
    def start(self):
        """Start the scheduler thread."""
        if self.running:
            logger.warning("Scheduler is already running")
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self.thread.start()
        
        logger.info("Task scheduler started")
    
    def stop(self):
        """Stop the scheduler thread."""
        if not self.running:
            logger.warning("Scheduler is not running")
            return
        
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        
        logger.info("Task scheduler stopped")
    
    def _scheduler_loop(self):
        """Main scheduler loop."""
        while self.running:
            try:
                # Check for tasks that need to run
                for task_name, task in list(self.tasks.items()):
                    if task.should_run():
                        # Execute the task in a separate thread
                        thread = threading.Thread(
                            target=self._execute_task,
                            args=(task,),
                            daemon=True
                        )
                        thread.start()
                
                # Save task state
                self.save_tasks()
                
                # Sleep for a short time
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Error in scheduler loop: {str(e)}", exc_info=True)
                time.sleep(5)  # Sleep longer on error
    
    def _execute_task(self, task):
        """
        Execute a task in a separate thread.
        
        Args:
            task: Task to execute
        """
        try:
            task.execute()
            self.save_tasks()
        except Exception as e:
            logger.error(f"Error executing task '{task.name}': {str(e)}", exc_info=True)
    
    def add_interval_task(self, name: str, command: str, interval: int, 
                         description: Optional[str] = None) -> bool:
        """
        Add an interval-based task.
        
        Args:
            name: Task name
            command: Command to execute
            interval: Interval in minutes
            description: Task description
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if name in self.tasks:
                logger.warning(f"Task '{name}' already exists")
                return False
            
            task = Task(
                name=name,
                command=command,
                interval=interval,
                description=description
            )
            
            self.tasks[name] = task
            self.save_tasks()
            
            logger.info(f"Added interval task '{name}' with interval {interval} minutes")
            return True
            
        except Exception as e:
            logger.error(f"Error adding interval task: {str(e)}", exc_info=True)
            return False
    
    def add_cron_task(self, name: str, command: str, cron: str, 
                     description: Optional[str] = None) -> bool:
        """
        Add a cron-based task.
        
        Args:
            name: Task name
            command: Command to execute
            cron: Cron expression
            description: Task description
            
        Returns:
            True if successful, False otherwise
        """
        if not CRONITER_AVAILABLE:
            logger.error("Cannot add cron task: croniter package not installed")
            return False
        
        try:
            if name in self.tasks:
                logger.warning(f"Task '{name}' already exists")
                return False
            
            # Validate cron expression
            try:
                croniter.croniter(cron, datetime.now())
            except Exception as e:
                logger.error(f"Invalid cron expression '{cron}': {str(e)}")
                return False
            
            task = Task(
                name=name,
                command=command,
                cron=cron,
                description=description
            )
            
            self.tasks[name] = task
            self.save_tasks()
            
            logger.info(f"Added cron task '{name}' with expression '{cron}'")
            return True
            
        except Exception as e:
            logger.error(f"Error adding cron task: {str(e)}", exc_info=True)
            return False
    
    def remove_task(self, name: str) -> bool:
        """
        Remove a task.
        
        Args:
            name: Task name
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if name not in self.tasks:
                logger.warning(f"Task '{name}' not found")
                return False
            
            del self.tasks[name]
            self.save_tasks()
            
            logger.info(f"Removed task '{name}'")
            return True
            
        except Exception as e:
            logger.error(f"Error removing task: {str(e)}", exc_info=True)
            return False
    
    def get_task(self, name: str) -> Optional[Task]:
        """
        Get a task by name.
        
        Args:
            name: Task name
            
        Returns:
            Task instance, or None if not found
        """
        return self.tasks.get(name)
    
    def list_tasks(self) -> List[Dict[str, Any]]:
        """
        List all tasks.
        
        Returns:
            List of task dictionaries
        """
        return [task.to_dict() for task in self.tasks.values()]
    
    def save_tasks(self) -> bool:
        """
        Save tasks to storage file.
        
        Returns:
            True if successful, False otherwise
        """
        if not self.storage_path:
            return False
        
        # Check if the path is writable before attempting to save
        if not self._check_path_writable(self.storage_path):
            logger.error(f"Cannot save tasks: path '{self.storage_path}' is not writable")
            return False
        
        try:
            tasks_data = [task.to_dict() for task in self.tasks.values()]
            
            # Create a temporary file first to avoid corruption if the write fails
            temp_path = f"{self.storage_path}.tmp"
            with open(temp_path, 'w') as f:
                json.dump(tasks_data, f, indent=2)
            
            # Rename the temporary file to the actual file
            # This is more atomic and reduces the risk of data corruption
            if os.path.exists(self.storage_path):
                os.replace(temp_path, self.storage_path)
            else:
                os.rename(temp_path, self.storage_path)
            
            return True
            
        except PermissionError:
            logger.error(f"Permission denied when saving tasks to '{self.storage_path}'")
            return False
        except Exception as e:
            logger.error(f"Error saving tasks: {str(e)}", exc_info=True)
            return False
    
    def load_tasks(self) -> bool:
        """
        Load tasks from storage file.
        
        Returns:
            True if successful, False otherwise
        """
        if not self.storage_path:
            return False
        
        try:
            if not os.path.exists(self.storage_path):
                logger.info(f"Task storage file '{self.storage_path}' does not exist")
                return False
            
            # Check if the file is readable
            if not os.access(self.storage_path, os.R_OK):
                logger.error(f"File '{self.storage_path}' is not readable. Cannot load tasks.")
                return False
            
            with open(self.storage_path, 'r') as f:
                tasks_data = json.load(f)
            
            self.tasks = {}
            for task_data in tasks_data:
                task = Task.from_dict(task_data)
                self.tasks[task.name] = task
            
            logger.info(f"Loaded {len(self.tasks)} tasks from storage")
            return True
            
        except PermissionError:
            logger.error(f"Permission denied when reading tasks from '{self.storage_path}'")
            return False
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON format in task file '{self.storage_path}'")
            return False
        except Exception as e:
            logger.error(f"Error loading tasks: {str(e)}", exc_info=True)
            return False
    
    def get_upcoming_tasks(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get upcoming tasks sorted by next run time.
        
        Args:
            limit: Maximum number of tasks to return
            
        Returns:
            List of task dictionaries
        """
        tasks = [task for task in self.tasks.values() if task.next_run is not None]
        tasks.sort(key=lambda task: task.next_run)
        
        return [task.to_dict() for task in tasks[:limit]]
    
    def get_recent_tasks(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get recently executed tasks sorted by last run time.
        
        Args:
            limit: Maximum number of tasks to return
            
        Returns:
            List of task dictionaries
        """
        tasks = [task for task in self.tasks.values() if task.last_run is not None]
        tasks.sort(key=lambda task: task.last_run, reverse=True)
        
        return [task.to_dict() for task in tasks[:limit]]
    
    def _check_path_writable(self, path: str) -> bool:
        """
        Check if a path is writable by the application.
        
        Args:
            path: Path to check
            
        Returns:
            True if writable, False otherwise
        """
        # Get the directory containing the file
        directory = os.path.dirname(path)
        
        # Check if directory exists and is writable
        if not os.path.exists(directory):
            logger.warning(f"Directory '{directory}' does not exist")
            return False
        
        if not os.access(directory, os.W_OK):
            logger.warning(f"Directory '{directory}' is not writable. Task persistence may fail.")
            return False
        
        # If file exists, check if it's writable
        if os.path.exists(path):
            if not os.access(path, os.W_OK):
                logger.warning(f"File '{path}' is not writable. Task persistence may fail.")
                return False
        
        return True
